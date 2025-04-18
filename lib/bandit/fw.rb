class Bandit
  module FW
    # TODO: different backends: ufw, iptables; hopefully bulk updateable
    class Abstract
      def ban(ip, jail) = raise NotImplementedError, "#{__method__} not implemented"
      def unban(ip) = raise NotImplementedError, "#{__method__} not implemented"
      def start(ips) = raise NotImplementedError, "#{__method__} not implemented"
    end

    class Null < Abstract
      def initialize(_) = nil
      def ban(ip, jail) = nil
      def unban(ip)     = nil
      def start(ips)    = nil
    end

    class Logger < Abstract
      attr_accessor :logger
      def initialize logger
        self.logger = logger
      end
      def log(fmt, *args) = logger.info "FW #{fmt}" % [*args]
      def ban(ip, jail)   = log "BAN %s %s", jail, ip
      def unban(ip)       = log "UNBAN %s", ip
      def start(ips)      = log "START BAN %d IPS", ips.size
    end

    class IpSet < Logger
      def _restore(&b)
        IO.popen "ipset restore -exist", "w", &b
      end

      def ban ip, jail
        super

        _restore do |io|
          io.puts "add bandit %s" % [ip]
        end
      end

      def unban ip
        super

        _restore do |io|
          io.puts "del bandit %s" % [ip]
        end
      end

      def start ips
        super

        _restore do |io|
          io.puts "create bandit hash:ip -exist"
          io.puts "create bandit_tmp hash:ip"
          io.puts ips.map { |ip| "add bandit_tmp #{ip}" }
          io.puts "swap bandit_tmp bandit"
          io.puts "destroy bandit_tmp"
        end
      end
    end
  end
end
