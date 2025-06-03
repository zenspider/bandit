Bandit.add_jail(
  :nginx,
  # pre-filters:
  /^(?<content>\S+ \S+ \S+ \[.*?\] ".*?" [45]\d\d)|(?<content>SSL_do_handshake.. failed .SSL: error:0A00006C:SSL routines::bad key share.*?client: \S+)/,

  # content filters:
  /SSL_do_handshake.+?client: #{HOST_IP}/,
  /^#{HOST_IP} - - \[.*?\] "[^"]*(?:\\x\h{2}){3,}[^"]*?" 400/,
  /^#{HOST_IP} - - \[.*?\] "[^"]*\/\.env[^"]*?" 404/,
  /^#{HOST_IP} - - \[.*?\] "POST [^"]*?\/[^"]*?" 405/,
  /^#{HOST_IP} - - \[.*?\] "[^"]*\/phpinfo/,
  /^#{HOST_IP} - - \[.*?\] "[^"]*\/eval-stdin.php/,
  /^#{HOST_IP} - - \[.*?\] "[^"]*\/xmlrpc\.php/,
  /^#{HOST_IP} - - \[.*?\] "[^"]*\/info\.php/,
  /^#{HOST_IP} - - \[.*?\] "[^"]*\/wp-login\.php/,
  /^#{HOST_IP} - - \[.*?\] "[^"]*(?:\.\.\/){3,}/,
  /^#{HOST_IP} - - \[.*?\] "POST [^"]*" 404/,
)
