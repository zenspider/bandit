Bandit.add_jail(
  :wordpress,

  /^(?<content>.*?\.php.*?"\s[45]\d\d)
  |^(?<content>\S+\ \S+\ \S+\ \[.*?\]\ "POST.*?"\ 200)
  |^(?<content>\S+\ \S+\ \S+\ \[.*?\]\ "[^"]*"\ 40\d)
  |^(?<content>.*AH01797:\ client\ denied.*?:\ \S+)/x,

  /^#{HOST_IP} .*? "POST [^"]+" 200/,
  /^#{HOST_IP} .*? "GET [^"]*?\/\.env[^"]*?" 404/,
  /^#{HOST_IP} .*? 400/,
  /^#{HOST_IP} .*? "GET [^"]*\/\.git\/[^"]*?" 404/,
  /^#{HOST_IP} .*? "POST [^"]+" 403/,
  /^#{HOST_IP} .*? "[^"]*?(?:wp-)?admin[^"]*?" 40\d/,
  /^#{HOST_IP} .*? "[^"]*?(?:\\x\h{2}){3,}[^"]*?" 404/,
  /^#{HOST_IP} .*? "[^"]*?php[-_]?info[^"]*?" 40\d/,
  /^#{HOST_IP} .*? "[^"]*aws[^"]*" 404/,
  /^#{HOST_IP} .*? 500/,
  /^#{HOST_IP} .*? 408/,
  /^#{HOST_IP} .*? "[^"]*\.json[^"]*" 404/,

  /^\[.*?\] \[access_compat:error\] \[.*?\] \[client #{HOST_IP}:\d+\] AH01797: client denied by server configuration: .*?xmlrpc.php/,

  /^#{HOST_IP} .*? "GET [^"]*\/plugins\/[^"]*?" 404/,
  /^#{HOST_IP} .*? "GET [^"]*info[^"]*?" 404/,
  /^#{HOST_IP} .*? "CONNECT[^"]*" 404/,
  /^#{HOST_IP} .*? "GET [^"]*xmlrpc[^"]*?" 40\d/,
  /^#{HOST_IP} .*? "[^"]*\/\.well-known[^"]*" 404/,
  /^#{HOST_IP} .*? "[^"]*\/eval-stdin\.php[^"]*" 404/,
)
