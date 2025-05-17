Bandit.jail_offset(:mail, -3)
Bandit.add_jail(
  :mail,
  %r%
    .*?
    postfix(-\w+)?/smtp[ds]
    .*?
    (?:
      warning:
      | (?:
          \w+:\ reject:
        | (?:improper\ command\ pipelining|too\ many\ errors)\ after\ \S+
        )
      | (?:
          lost\ connection\ after(?!\ DATA)\ [A-Z]+
        | disconnect(?=\ from\ \S+(?:\ \S+=\d+)*\ auth=0/(?:[1-9]|\d\d+))
        )
     )\s
     (?<content>.+)
  %x,

  /^[^\[]*\[#{HOST_IP}\](?::\d+)?: SASL ((?i)LOGIN|PLAIN|(?:CRAM|DIGEST)-MD5) authentication failed:(?! Connection lost to authentication server)/,
  /^RCPT from [^\[]*\[#{HOST_IP}\](?::\d+)?: 55[04] 5\.7\.1\s/,
  /^RCPT from [^\[]*\[#{HOST_IP}\](?::\d+)?: 45[04] 4\.7\.\d+ (?:Service unavailable\b|Client host rejected: cannot find your (reverse )?hostname\b)/,
  /^RCPT from [^\[]*\[#{HOST_IP}\](?::\d+)?: 450 4\.7\.\d+ (<[^>]*>)?: Helo command rejected: Host not found\b/,
  /^(?:RCPT|EHLO) from [^\[]*\[#{HOST_IP}\](?::\d+)?: 504 5\.5\.\d+ (<[^>]*>)?: Helo command rejected: need fully-qualified hostname\b/, # EHLO -> (?:RCPT|EHLO)
  /^(RCPT|VRFY) from [^\[]*\[#{HOST_IP}\](?::\d+)?: 550 5\.1\.1\s/,
  /^RCPT from [^\[]*\[#{HOST_IP}\](?::\d+)?: 450 4\.1\.\d+ (<[^>]*>)?: Sender address rejected: Domain not found\b/,
  /^RCPT from [^\[]*\[#{HOST_IP}\](?::\d+)?: 554 5\.1\.\d+ (<[^>]*>)?: Sender address rejected: Domain not found\b/, # added to change reject code
  /^hostname \S+ does not resolve to address #{HOST_IP}: No address associated with hostname/,

  /^from [^\[]*\[#{HOST_IP}\](?::\d+)?:?/,
)
