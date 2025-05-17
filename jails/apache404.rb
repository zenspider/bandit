Bandit.add_jail(
  :apache404,
  /(?<content>BAN .*)/,
  /BAN #{HOST_IP}/
)
