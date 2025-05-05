class Bandit
  module FW
    # TODO: different backends: ufw, iptables; hopefully bulk updateable
    class Abstract
      def ban(ip)   = raise NotImplementedError, "#{__method__} not implemented"
      def unban(ip) = raise NotImplementedError, "#{__method__} not implemented"

      def log(fmt, *args) = puts "%s #{fmt}" % [Time.now, *args]
    end

    class Logger < Abstract
      attr_accessor :verbose
      def initialize verbose
        self.verbose = verbose
      end
      def ban(ip)   = (verbose and log "FW BAN %s", ip)
      def unban(ip) = (verbose and log "FW UNBAN %s", ip)
    end
  end
end
