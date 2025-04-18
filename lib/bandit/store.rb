class Hash
  def join(a:"=", b:" ") = map { |pair| pair.join a }.join b
end

class Bandit

  ##
  # Bandit's Storage system.
  # --
  # database schema
  #
  # table ban:
  #
  #   ip         TEXT         PRIMARY KEY
  #   allowed    BOOL         DEFAULT false
  #   count      INT          DEFAULT 0
  #   unban_at   NULL | date  DEFAULT NULL
  #   updated_at date         DEFAULT now
  #   created_at date         DEFAULT now
  #
  # such that:
  #
  #   allow: <ip>  true     0  NULL        now  <created_at>
  #   ban  : <ip>  false  1+n  2025-06-01  now  <created_at>
  #   unban: <ip>  false    n  NULL        now  <created_at>
  #
  # ban time = 2**(count+offset) = 1 2 4 8 16 32 64 128 ... hours
  #
  # There is also a dns table for caching dns lookups, but it is only
  # populated outside of bandit and only referenced by the report
  # command.

  module Store

    # An Abstract pattern for Stores. Defines the minimum API.
    class Abstract
      def __no(name)    = raise NotImplementedError, "#{name} not implemented" # :nodoc:

      # Mark +ip+ as allowed (never banned).
      def allow(ip)     = __no __method__

      # Mark +ip+ as banned.
      def ban(ip, jail) = __no __method__

      # Mark +ip+ as unbanned (record is kept, but unban_at is cleared).
      def unban(ip)     = __no __method__

      # Remove +ip+ from Store.
      def rm(ip)        = __no __method__

      # Return all expired bans (unban_at in past).
      def expired       = __no __method__

      # Return all purged bans (updated_at older than (4 + count - 1) weeks ago).
      def purge         = __no __method__

      # Return all active ban IPs.
      def active        = __no __method__

      # Return next unban time.
      def next_unban    = __no __method__

      # Print a report of current culprits.
      def report        = __no __method__
    end

    # A Null pattern for Stores.
    class Null < Abstract
      # :stopdoc:
      def initialize(_) = nil
      def allow(ip)     = nil
      def ban(ip, jail) = nil
      def unban(ip)     = nil
      def rm(ip)        = nil
      def expired       = []
      def purge         = nil
      def active        = []
      def next_unban    = raise "no?"
      def report        = nil
      # :startdoc:
    end

    require "sqlite3"

    ##
    # Use sqlite as Store.

    class SQLiteDB < Abstract
      # :stopdoc:
      attr_accessor :logger
      attr_accessor :db
      attr_accessor :path

      def initialize logger, path: "bandit.db"
        self.logger = logger
        self.path   = path
        self.db = SQLite3::Database.new path, strict: true
        db.busy_timeout = 1_500 # ms
        db.results_as_hash = true

        db.execute_batch <<~SQL
          CREATE TABLE IF NOT EXISTS bans (
            ip         TEXT         PRIMARY KEY,
            jail       TEXT         DEFAULT NULL,
            allowed    INT NOT NULL DEFAULT FALSE,
            count      INT NOT NULL DEFAULT 0,
            unban_at   TEXT         DEFAULT NULL,
            updated_at TEXT         DEFAULT (datetime('now', 'localtime')),
            created_at TEXT         DEFAULT (datetime('now', 'localtime'))
          ) STRICT;

          CREATE TABLE IF NOT EXISTS dns (
            ip         TEXT         PRIMARY KEY,
            name       TEXT NOT NULL,
            updated_at TEXT         DEFAULT (datetime('now', 'localtime')),
            created_at TEXT         DEFAULT (datetime('now', 'localtime'))
          ) STRICT;

          CREATE UNIQUE INDEX IF NOT EXISTS bans_ips ON bans (ip);
          CREATE UNIQUE INDEX IF NOT EXISTS dns_ips  ON dns  (ip);
        SQL
      end

      def log(name, args) = logger.info "DB #{name} #{args.join}"
      # :startdoc:

      ##
      # Mark +ip+ as allowed (never banned). Will restore a current
      # ban to allowed.

      def allow ip
        row = db.get_first_row <<~SQL, [ip, 1]
          INSERT INTO bans (ip, jail, allowed) VALUES (?, 'allowed', ?)
          ON CONFLICT DO UPDATE SET
            jail       = 'allowed',
            allowed    = 1,
            unban_at   = NULL,
            count      = 0,
            updated_at = datetime('now', 'localtime')
          RETURNING ip
        SQL
        log "ALLOW", row
      end

      ##
      # Mark +ip+ as banned by +jail+. If the ban in new, calculates
      # the ban time and sets count to 1. If the ban already exists,
      # calculates new ban time and increments count.
      #
      # Uses jail's +offset+ to calculate ban time:
      #
      #   2 ** (count + offset) hours
      #
      # such that an offset of -3 would start the first ban at:
      #
      #   2 ** -3 = 1/8 hours
      #
      # but an offset of 1 would start the first ban at:
      #
      #   2 ** 1 = 2 hours
      #
      # Returns nil if no such ban.

      def ban ip, jail
        offset = Bandit.jail_offsets[jail.to_sym]
        jail = jail.to_s
        row = db.get_first_row <<~SQL, {ip:, jail:, offset:}
          INSERT INTO bans (ip, jail, count, unban_at)
            VALUES (:ip, :jail,
                    1,
                    datetime('now',
                      format('+%f hours', power(2, :offset)),
                      'localtime'))

          ON CONFLICT DO UPDATE SET
            jail       = :jail,
            unban_at   = datetime('now',
                           format('+%f hours', power(2, count+:offset)),
                           'localtime'),
            count      = count + 1,
            updated_at = datetime('now', 'localtime')
            WHERE allowed != 1
              AND 86400.0*(julianday('now', 'localtime') - julianday(updated_at)) > 1

          RETURNING ip, jail, count, unban_at AS until
        SQL

        return unless row

        log "BAN", row

        row
      end

      ##
      # Mark +ip+ as unbanned. Returns nil if no such ban.

      def unban ip
        row = db.get_first_row <<~SQL, [ip]
          UPDATE bans
          SET unban_at = NULL, updated_at = datetime('now', 'localtime')
          WHERE ip = ?
          RETURNING ip, jail, count
        SQL

        return unless row

        log "UNBAN", row
      end

      ##
      # Removes +ip+ from Store. Returns nil if no such ban.

      def rm ip
        row = db.get_first_row <<~SQL, [ip]
          DELETE from bans WHERE ip = ? RETURNING ip
        SQL

        return unless row

        log "RM", row
      end

      # :stopdoc:

      def expired
        db.execute(<<~SQL).flat_map(&:values)
          SELECT ip FROM bans
          WHERE NOT allowed
            AND unban_at
            AND julianday(unban_at) < julianday('now', 'localtime')
        SQL
      end

      def purge
        # 4 + (count - 1) weeks from updated_at, 28 day minimum + penalty for offenses
        rows = db.execute(<<~SQL)
          DELETE FROM bans
          WHERE NOT allowed
            AND julianday(updated_at, format('+%d days', 7 * (4 + count - 1))) <
                julianday('now', 'localtime')
          RETURNING ip
        SQL

        rows.each do |row|
          log "PURGE", row
        end

        nil
      end

      def active
        db.execute(<<~SQL).map { |h| h["ip"] }
          SELECT ip FROM bans
          WHERE allowed != 1
            AND unban_at
            AND julianday(unban_at) > julianday('now', 'localtime')
          ORDER BY ip ASC
        SQL
      end

      def next_unban
        db.get_first_value(<<~SQL)
          SELECT
            86400.0 * (julianday(unban_at) - julianday('now', 'localtime')) AS t
            FROM bans
            WHERE unban_at NOT NULL AND NOT allowed
          UNION
          SELECT
            86400.0 * (
              julianday(updated_at, format('+%d days', 7 * (4 + count - 1))) -
              julianday('now', 'localtime')) AS t
            FROM bans
            WHERE NOT allowed
          ORDER BY t
          LIMIT 1
        SQL
      end

      def report
        system <<~"EOF"
            sqlite3 -column -header #{path} <<-SQL | sed -re 's/ +$//'
              SELECT bans.ip as ip, jail, count, unban_at, dns.name FROM bans
               LEFT OUTER JOIN dns ON bans.ip = dns.ip
               WHERE unban_at -- OR count > 1
               ORDER BY unban_at, count, ip, bans.updated_at
            SQL
            echo
            sqlite3 -column #{path} <<-SQL
              SELECT 'active'   AS cat, count(*) FROM bans WHERE unban_at UNION
              SELECT 'inactive' AS cat, count(*) FROM bans WHERE unban_at IS NULL UNION
              SELECT 'total'    AS cat, count(*) FROM bans
            SQL
        EOF
      end

      # :startdoc:
    end
  end
end
