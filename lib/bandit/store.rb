##
# database schema
#
# table ban:
#
# ip       TEXT         PRIMARY KEY
# allowed  BOOL         DEFAULT false
# count    INT          DEFAULT 0
# unban_at NULL | date  DEFAULT NULL
# updated_at date       DEFAULT now

# such that:
#   allow: <ip>   0 NULL       true  now
#   ban  : <ip> n+1 2025-06-01 false now
#   unban: <ip> n   NULL       false now

# count = ban: 2**n = 1 2 4 8 16 32 64 128 ... hours

class Bandit
  module Store
    class Abstract
      def __no(name)    = raise NotImplementedError, "#{name} not implemented"
      def allow(ip)     = __no __method__
      def ban(ip, jail) = __no __method__
      def unban(ip)     = __no __method__
      def rm(ip)        = __no __method__
      def expired       = __no __method__
      def purge         = __no __method__
      def dump          = __no __method__
      def active        = __no __method__
      def next_unban    = __no __method__
    end

    class Null < Abstract
      def initialize(_) = nil
      def allow(ip)     = nil
      def ban(ip, jail) = nil
      def unban(ip)     = nil
      def rm(ip)        = nil
      def expired       = []
      def purge         = nil
      def dump          = nil
      def active        = []
      def next_unban    = raise "no?"
    end

    require "sqlite3"
    class SQLiteDB < Abstract
      attr_accessor :logger
      attr_accessor :db

      def initialize logger, path: "bandit.db"
        self.logger = logger
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

      def log(fmt, *args) = logger.info "DB #{fmt}" % [*args]

      def allow ip
        log "ALLOW %s", ip
        db.execute <<~SQL, [ip, 1]
          INSERT INTO bans (ip, jail, allowed) VALUES (?, 'allowed', ?)

          ON CONFLICT DO UPDATE SET
            jail       = 'allowed',
            allowed    = 1,
            unban_at   = NULL,
            count      = 0,
            updated_at = datetime('now', 'localtime')
        SQL
      end

      def ban ip, jail
        offset = Bandit.jail_offsets[jail.to_sym]
        jail = jail.to_s
        ban, = db.execute <<~SQL, {ip:, jail:, offset:}
          INSERT INTO bans (ip, jail, count, unban_at)
            VALUES (:ip, :jail,
                    1,
                    datetime('now',
                      format('+%f hours', power(2, min(:offset, 15))),
                      'localtime'))

          ON CONFLICT DO UPDATE SET
            jail       = :jail,
            unban_at   = datetime('now',
                           format('+%f hours', power(2, min(count+:offset, 15))),
                           'localtime'),
            count      = count + 1,
            updated_at = datetime('now', 'localtime')
            WHERE allowed != 1
              AND 86400.0*(julianday('now', 'localtime') - julianday(updated_at)) > 1

          RETURNING count, unban_at
        SQL

        return unless ban

        log "BAN %s %s count=%d until=%s", jail, ip, *ban.values
        ban
      end

      def unban ip
        ban, = db.execute <<~SQL, [ip]
          UPDATE bans
          SET unban_at = NULL, updated_at = datetime('now', 'localtime')
          WHERE ip = ?
          RETURNING *
        SQL

        return unless ban

        log "UNBAN %s", ip
      end

      def rm ip
        ban, = db.execute <<~SQL, [ip]
          DELETE from bans WHERE ip = ? RETURNING *
        SQL

        return unless ban

        log "RM %s", ip
      end

      def expired
        db.execute(<<~SQL).flat_map(&:values)
          SELECT ip FROM bans
          WHERE NOT allowed
            AND unban_at
            AND julianday(unban_at) < julianday('now', 'localtime')
        SQL
      end

      def purge
        stale = Time.now - STALE_TIME
        db.execute(<<~SQL, stale.to_s).flat_map(&:values)
          DELETE FROM bans
          WHERE NOT allowed
            AND julianday(updated_at) < julianday(?, 'localtime')
          RETURNING *
        SQL
      end

      def dump
        first = true
        db.execute2 "SELECT * FROM bans ORDER BY allowed DESC, count DESC, ip ASC" do |row|
          if first then
            puts row.join "\t"
            first = false
          else
            puts row.values.map { |v| v.nil? ? "NULL\t\t" : v }.join "\t"
          end
        end
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
          SELECT 86400.0 * (julianday(unban_at) - julianday('now', 'localtime')) AS t
          FROM bans
          WHERE unban_at NOT NULL and NOT allowed
          ORDER BY unban_at
          LIMIT 1
        SQL
      end
    end
  end
end
