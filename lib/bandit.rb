require_relative "bandit/store"
require_relative "bandit/fw"
require "syslog"
require "syslog/logger"

##
# Bandit is a dynamic firewall inspired by fail2ban but with the goal
# of being much simpler and easier to maintain and extend.

class Bandit
  # :stopdoc:
  VERSION = "1.0.0"
  HOUR       = 3_600
  DAY        = 24 * HOUR
  # :startdoc:

  # The time required for inactive bans to be removed from the database.
  STALE_TIME = 28 * DAY

  # A regexp to match IP addresses, to be used in recipes.
  HOST_IP = /(?<host_ip>\d+\.\d+\.\d+\.\d+)/

  # The firewall plugin to use. Defaults to Bandit::FW::Null.
  attr_accessor :fw

  # The database plugin to use. Defaults to Bandit::Store::Null.
  attr_accessor :store

  # The logger to use. Defaults to a Syslog::Logger instance.
  attr_accessor :logger

  # Returns all methods that start with "cmd_". See bin/bandit.
  def self.commands
    public_instance_methods
      .grep(/^cmd_/)
      .sort
      .map(&:to_s)
  end

  ##
  # Returns all known jails

  def self.jails               = @jails ||= {}

  ##
  # Add a jail named +n+, with a pre-match regexp +p+ and content
  # regexps +rs+ to the known jails.

  def self.add_jail(n, p, *rs) = jails[n] = [p, *rs]

  ##
  # Return all jail regular expressions in the form:
  #
  #   { pre_re => { content_re => jail_name, ... }, ... }

  def self.jail_regexps        = jails.to_h { |n, (pre, *res)| [pre, res.to_h { |re| [re, n] }] }

  ##
  # Load a jail named +name+ from jails/$name.rb. Relative to pwd.

  def self.load_jail(name)     = instance_eval File.read "jails/#{name}.rb"

  ##
  # Returns offsets for jails.

  def self.jail_offsets = @jail_offsets ||= Hash.new(0)

  ##
  # Defines an offset for jail named +name+ with offset +offset+. This
  # shifts the calculation
  #
  #   2 ** (count + offset) hours
  #
  # such that an offset of -3 would start the first ban at:
  #
  #   2 ** -3 = 1/8 hours
  #
  # but an offset of 1 would start the first ban at:
  #
  #   2 ** 1 = 2 hours

  def self.jail_offset(name, offset) = jail_offsets[name] = offset

  def self.cmd(name) = alias_method "cmd_#{name}", name # :nodoc:

  def initialize logger = Syslog::Logger.new("bandit") # :nodoc:
    self.logger  = logger
    self.fw      = FW::Null.new logger
    self.store   = Store::Null.new logger
  end

  ##
  # Allow an IP. Prevents that IP from ever being banned.

  def allow ip
    store.allow ip
  end
  cmd :allow

  ##
  # Unban an IP. Removes IP from the firewall and tells the database
  # to expire any current ban.

  def unban ip
    fw.unban ip
    store.unban ip
  end
  cmd :unban

  ##
  # Remove an IP. Removes IP from the firewall and deletes the entry
  # in the database.

  def rm ip
    fw.unban ip
    store.rm ip
  end
  cmd :rm

  ##
  # Ban an IP. Adds IP to the firewall and the database.
  #
  # Ban time is automatic and based on the number of times the IP has
  # been banned. Starting at (by default) 1 hour and doubling every
  # time after that. This shuts down repeat offenders quickly.
  #
  #   hours        days         weeks     months            years
  #   2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768
  #
  # Due to storage constraints in the database, the maximum ban is
  # 2^15th or 32768 hours, which is approximately 3.75 years.

  def ban ip, jail = :manual
    fw.ban ip, jail if store.ban ip, jail
  end
  cmd :ban

  ##
  # Ask the database to print out a report of current offenders.

  def report
    store.report
  end
  cmd :report

  ##
  # Used to unban expired bans and purge stale bans.
  # Internal, see #start.

  def update
    logger.debug "running updater"
    store.expired.each do |ban|
      unban ban
    end

    store.purge
  end

  ##
  # Start the firewall with current bans and create updater thread to
  # unban when bans expire as necessary.
  #
  # Internal.

  def start
    logger.info "starting bandit #{VERSION}"

    fw.start store.active

    updater = Thread.new do
      loop do
        t = (store.next_unban || HOUR).clamp(0, 300)
        if t > 0 then
          logger.debug "updater sleeping for %.2f seconds" % [t]
          sleep t
        end
        update
      end
    end

    at_exit { updater.kill }
  end

  ##
  # Return the pre-filter regular expressions.

  def jail_regexps = self.class.jail_regexps

  ##
  # Reads from +io+, applying jail pre-filters to find applicable
  # content, and then applying that jail's regexps to find culprit IP
  # addresses to ban.
  #
  # Returns a hash of counts. Helps identify unused regexps.

  def ingress io
    stats = Hash.new 0

    regexps = jail_regexps

    pre_res = regexps.keys

    regexps.values.flat_map(&:keys).each do |re| stats[re] = 0 end

    io.each_line do |line|
      stats[:line] += 1

      line.chomp!

      case line
      when *pre_res then
        md = Regexp.last_match

        content_res = regexps[md.regexp]

        case md[:content]
        when *content_res.keys then
          md = Regexp.last_match
          stats[md.regexp] += 1
          stats[:ban] += 1
          jail = content_res[md.regexp]

          ip = md[:host_ip]
          self.ban ip, jail
        end
      else
        stats[:miss] += 1
      end
    end

    stats
  rescue Interrupt
    warn "killed"
    stats
  end
end
