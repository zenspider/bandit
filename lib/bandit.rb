require_relative "bandit/time_exts"
require_relative "bandit/store"
require_relative "bandit/fw"
require "syslog"
require "syslog/logger"

class Bandit
  VERSION = "1.0.0"

  HOUR       = 3_600
  DAY        = 24 * HOUR
  STALE_TIME = 28 * DAY

  HOST_IP = /(?<host_ip>\d+\.\d+\.\d+\.\d+)/

  attr_accessor :fw
  attr_accessor :store
  attr_accessor :logger

  def self.commands
    public_instance_methods
      .grep(/^cmd_/)
      .sort
      .map(&:to_s)
  end

  def self.jails               = @jails ||= {}
  def self.add_jail(n, p, *rs) = jails[n] = [p, *rs]
  def self.jail_regexps        = jails.values.to_h { |a| [a.first, a.drop(1)] }
  def self.load_jail(name)     = instance_eval File.read "jails/#{name}.rb"

  def self.cmd(name) = alias_method "cmd_#{name}", name

  def initialize logger = Syslog::Logger.new("bandit")
    self.logger  = logger
    self.fw      = FW::Logger.new logger
    self.store   = Store::Logger.new logger

    logger.info "starting bandit #{VERSION}"
  end

  cmd def allow ip
    store.allow ip
  end

  cmd def unban ip
    fw.unban ip
    store.unban ip
  end

  cmd def ban ip
    fw.ban ip if store.ban ip
  end

  cmd def update # run every hour? minute?
    store.expired.each do |ban|
      unban ban
    end

    store.purge
  end

  cmd def dump
    store.dump
  end

  cmd def export
    puts store.active.map { |ip| "add bandit %s" % [ip] }
  end

  def start
    fw.start store.active

    t = Thread.new do
      loop do
        sleep 10
        update
      end
    end

    at_exit { t.kill }
  end

  def jail_regexps = self.class.jail_regexps

  def ingress io
    stats = Hash.new 0

    regexps = jail_regexps
    pre_res = regexps.keys

    regexps.values.flatten.each do |re| stats[re] = 0 end

    io.each_line do |line|
      stats[:line] += 1

      line.chomp!

      case line
      when *pre_res then
        md = Regexp.last_match

        content_res = regexps[md.regexp]
        content = md[:content]

        case content
        when *content_res then
          md = Regexp.last_match
          stats[md.regexp] += 1
          stats[:ban] += 1

          ip = md[:host_ip]
          self.ban ip
        end
      else
        stats[:miss] += 1
      end
    end

    stats
  end
end
