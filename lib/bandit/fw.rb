class Bandit
  module FW
    # TODO: different backends: ufw, iptables; hopefully bulk updateable
    class Abstract
      def ban(ip)   = raise NotImplementedError, "#{__method__} not implemented"
      def unban(ip) = raise NotImplementedError, "#{__method__} not implemented"

      def log(fmt, *args) = puts "%s #{fmt}" % [Time.now, *args]
    end

    class Logger < Abstract
      def ban(ip)   = puts "%s FW BAN %s"   % [Time.now, ip]
      def unban(ip) = puts "%s FW UNBAN %s" % [Time.now, ip]
    end
  end
end
