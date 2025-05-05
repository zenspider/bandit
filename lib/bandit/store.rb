##
# database schema
#
# table ban:
#
# ip
# allowed  BOOL         DEFAULT false
# count    INT          DEFAULT 0
# unban_at NULL | date  DEFAULT NULL
# updated_at date       DEFAULT today

# such that:
#   allow: <ip>   0 NULL       true  now
#   ban  : <ip> n+1 2025-06-01 false now
#   unban: <ip> n   NULL       false now

# count = ban: 2**n = 1 2 4 8 16 32 64 128 ... hours? days?

class Bandit
  module Store
    # TODO: different backends: sqlite3 direct, AR, Sequel?

    class Abstract
      def allow(ip) = raise NotImplementedError, "#{__method__} not implemented"
      def ban(ip)   = raise NotImplementedError, "#{__method__} not implemented"
      def unban(ip) = raise NotImplementedError, "#{__method__} not implemented"
      def expired   = raise NotImplementedError, "#{__method__} not implemented"
      def purge     = raise NotImplementedError, "#{__method__} not implemented"
      def dump      = raise NotImplementedError, "#{__method__} not implemented"

      def log(fmt, *args) = puts "%s #{fmt}" % [Time.now, *args]
    end

    class Logger < Abstract
      def allow(ip) = log "STORE %s %s", __method__.upcase, ip
      def ban(ip)   = log "STORE %s %s", __method__.upcase, ip
      def unban(ip) = log "STORE %s %s", __method__.upcase, ip
      def expired   = (log "STORE %s"  , __method__.upcase; [])
      def purge     = log "STORE %s"   , __method__.upcase
      def dump      = log "STORE %s"   , __method__.upcase
    end

    require "sqlite3"
    class SQLiteDB < Logger
      attr_accessor :db
      def initialize
        self.db = SQLite3::Database.new "bandit.db"
        db.busy_timeout = 1_500 # ms
        db.results_as_hash = true

        db.execute <<~SQL
          CREATE TABLE IF NOT EXISTS bans (
            ip         TEXT         PRIMARY KEY,
            allowed    INT NOT NULL DEFAULT FALSE,
            count      INT NOT NULL DEFAULT 0,
            unban_at   TEXT         DEFAULT NULL,
            updated_at TEXT         DEFAULT NULL,
            created_at TEXT         DEFAULT (datetime('now'))
          ) STRICT;

          CREATE INDEX IF NOT EXISTS bans_ips ON bans (ip);
        SQL
      end

      def allow ip
        super
        db.execute <<~SQL, [ip, 1]
          INSERT INTO bans (ip, allowed) VALUES (?, ?) ON CONFLICT DO NOTHING
        SQL
      end

      def ban ip
        ban, = db.execute <<~SQL, [ip]
          INSERT INTO bans (ip, count, unban_at, updated_at)
            VALUES (?,
                    1,
                    datetime("now", "localtime", format("+%d hours", 1)),
                    datetime("now", "localtime"))

          ON CONFLICT DO UPDATE SET
            unban_at = datetime("now", "localtime", format("+%d hours", power(2, min(count, 15)))),
            count = count + 1,
            updated_at = datetime("now", "localtime")
            WHERE allowed != 1

          RETURNING count, unban_at
        SQL

        return unless ban

        log "STORE BAN %s count=%d until=%s", ip, *ban.values
        ban
      end

      def unban ip
        ban, = db.execute <<~SQL, [ip]
          UPDATE bans
          SET unban_at = NULL, updated_at = datetime("now", "localtime")
          WHERE ip = ?
          RETURNING *
        SQL

        return unless ban

        log "STORE UNBAN %s", ip
      end

      def expired
        db.execute(<<~SQL).flat_map(&:values)
          SELECT ip FROM bans
          WHERE NOT allowed
            AND unixepoch(unban_at, "localtime") < unixepoch("now", "localtime")
        SQL
      end

      def purge
        stale = Time.now - STALE_TIME
        db.execute(<<~SQL, stale.to_s).flat_map(&:values)
          DELETE FROM bans
          WHERE NOT allowed
            AND unixepoch(updated_at, "localtime") < unixepoch(?, "localtime")
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
    end
  end
end
