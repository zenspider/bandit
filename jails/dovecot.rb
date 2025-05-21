Bandit.jail_offset(:dovecot, -3)
Bandit.add_jail(
  :dovecot,

  /^.*?dovecot: (?:pop3|imap|managesieve|submission)-login: (?<content>.+)$/,

  # 324:
  /^(?:Aborted login|Disconnected|Remote closed connection|Client has quit the connection)(?::(?: [^ \(]+)+)? \((?:no auth attempts|disconnected before auth was ready,|client didn't finish \S+ auth,)(?: (?:in|waited) \d+ secs)?\):(?: user=<[^>]*>,)?(?: method=\S+,)? rip=#{HOST_IP}(?:[^>]*(?:, session=<\S+>)?)\s*$/,


  # 22:
  /^(?:Aborted login|Disconnected|Remote closed connection|Client has quit the connection)(?::(?: [^ \(]+)+)? \((?:auth failed, \d+ attempts(?: in \d+ secs)?|tried to use (?:disabled|disallowed) \S+ auth|proxy dest auth failed)\):(?: user=<(?<user>[^>]*)>,)?(?: method=\S+,)? rip=#{HOST_IP}(?:[^>]*(?:, session=<\S+>)?)\s*$/,
)
