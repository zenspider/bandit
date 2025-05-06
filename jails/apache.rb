Bandit.add_jail(
  :apache,
  /(?<content>BAN .*)/,
  /BAN #{HOST_IP}/
)
