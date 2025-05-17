Bandit.add_jail(
  :sshd,
  /\bsshd\[\d+\]: (?:(?:error|fatal): (?:PAM: )?)?(?<content>.+)$/,

  /^(Connection (?:closed|reset)|Disconnected) (?:by|from)(?: (?:invalid|authenticating) user (?<user>\S+|.*?))? #{HOST_IP}(?: (?:port \d+|on \S+)){0,2}\s+\[preauth\]\s*$/, # 3604
  /^Received disconnect from #{HOST_IP}(?: (?:port \d+|on \S+)){0,2}:\s*11:.*?\[preauth\]/, # 2320
  /^[Ii](?:llegal|nvalid) user (?<user>.*?) from #{HOST_IP}(?: (?:port \d+|on \S+|\[preauth\])){0,3}\s*$/, # 1744
  # 665: TODO: needs to match multiple lines, not sure how I might want that yet
  # /^kex_exchange_identification: (?:[Cc]lient sent invalid protocol identifier|[Cc]onnection closed by remote host)/,
  /^Unable to negotiate with #{HOST_IP}(?: (?:port \d+|on \S+)){0,2}: no matching (?:(?:\w+ (?!found\b)){0,2}\w+) found./, # 177
  /^maximum authentication attempts exceeded for (?<user>.*) from #{HOST_IP}(?: (?:port \d+|on \S+)){0,2}(?: ssh\d*)?(?: (?:port \d+|on \S+|\[preauth\])){0,3}\s*$/, # 78
  /^Disconnecting(?: from)? (?:invalid|authenticating) user \S+ #{HOST_IP}(?: (?:port \d+|on \S+)){0,2}:\s*Change of username or service not allowed:\s*.*\[preauth\]\s*$/ # 5
)
