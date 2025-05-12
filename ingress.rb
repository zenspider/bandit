Bandit.load_jail :sshd      # all
Bandit.load_jail :apache404 if host "lust"
Bandit.load_jail :dovecot   if host "lust"
Bandit.load_jail :mail      if host "lust"
Bandit.load_jail :nginx     if host "seattlerb"
Bandit.load_jail :wordpress if host "kaiscantlin"
