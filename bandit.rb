#!/usr/bin/env -S ruby -w

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

class Time
  alias _to_s to_s
  alias _inspect inspect
  def to_s    = strftime "%F %T%z"
  def inspect = strftime "Time.parse(\"%F %T%z\")"
end

# class Concrete < Abstract
#   def allow ip
#     # INSERT INTO ban (IP, ALLOWED) VALUES (<ip>, true)
#     Ban.create! ip: ip, allowed: true
#   end
#
#   def ban ip
#     # add ip to fw
#     # datetime("now", format("+%d hours", 4));
#     #     date("now", format("+%d days", 4));
#
#     # ban = Ban.find_or_initialize_by(ip: ip)
#
#     # unless ban.allowed then
#     #   ban.count = ban.count + 1
#     #   ban.unban_at = Date.today + 2**count
#     #   ban.save!
#     # end
#   end
#
#   def unban ip
#     # UPDATE ban SET unban_at=null WHERE IP=<ip>
#     Ban.update!(ip, unban_at: nil)
#   end
#
#   def expired = Ban.where("unban_at < ?", Time.now)
#   def purge = Ban.where("updated_at < ?", Time.now - STALE_TIME).delete_all
# end
