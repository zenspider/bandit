class Bandit
  ##
  # Bandit's firewall system.

  module FW
    # An Abstract pattern for firewalls. Defines the minimum API.
    class Abstract
      def __no(name)    = raise NotImplementedError, "#{name} not implemented" # :nodoc:

      # Ban +ip+ for +jail+.
      def ban(ip, jail) = __no __method__

      # Unban +ip+.
      def unban(ip)     = __no __method__

      # Start the firewall.
      def start(ips)    = __no __method__
    end

    # A Null pattern for firewalls
    class Null < Abstract
      # :stopdoc:
      def initialize(_) = nil
      def ban(ip, jail) = nil
      def unban(ip)     = nil
      def start(ips)    = nil
      # :startdoc:
    end

    ##
    # Firewall plugin for ipset.

    class IpSet < Abstract
      attr_accessor :logger # :nodoc:

      def initialize logger # :nodoc:
        self.logger = logger
      end

      def log(fmt, *args) = logger.info "FW #{fmt}" % [*args] # :nodoc:

      def _restore(&b) # :nodoc:
        IO.popen "ipset restore -exist", "w", &b
      end

      ##
      # Ban +ip+ by immediately adding +ip+ to the bandit set.

      def ban ip, jail
        log "BAN ip=%s jail=%s", ip, jail

        _restore do |io|
          io.puts "add bandit %s" % [ip]
        end
      end

      ##
      # Unban +ip+ by immediately removing +ip+ from the bandit set.

      def unban ip
        log "UNBAN ip=%s", ip

        _restore do |io|
          io.puts "del bandit %s" % [ip]
        end
      end

      ##
      # Start the firewall, creating the set named bandit (as needed),
      # writing all current bans to a temporary set, and swapping them
      # in.

      def start ips
        log "START BAN count=%d", ips.size

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
