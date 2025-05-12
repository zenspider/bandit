class Bandit
  module FW
    # TODO: different backends: ufw, iptables; hopefully bulk updateable
    class Abstract
      def ban(ip)   = raise NotImplementedError, "#{__method__} not implemented"
      def unban(ip) = raise NotImplementedError, "#{__method__} not implemented"
    end

    class Logger < Abstract
      attr_accessor :logger
      def initialize logger
        self.logger = logger
      end
      def log(fmt, *args) = logger.info "FW #{fmt}" % [*args]
      def ban(ip)         = log "BAN %s", ip
      def unban(ip)       = log "UNBAN %s", ip
      def start(ips)      = log "START BAN %d IPS", ips.size
    end
      end
    end
  end
end
