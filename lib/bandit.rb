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
  # { pre_re => { content_re => jail_name, ... }, ... }
  def self.jail_regexps        = jails.to_h { |n, (pre, *res)| [pre, res.to_h { |re| [re, n] }] }
  def self.load_jail(name)     = instance_eval File.read "jails/#{name}.rb"

  def self.jail_offsets = @jail_offsets ||= Hash.new(0)
  def self.jail_offset(name, offset) = jail_offsets[name] = offset

  def self.cmd(name) = alias_method "cmd_#{name}", name

  def initialize logger = Syslog::Logger.new("bandit")
    self.logger  = logger
    self.fw      = FW::Null.new logger
    self.store   = Store::Null.new logger

    logger.info "starting bandit #{VERSION}"
  end

  cmd def allow ip
    store.allow ip
  end

  cmd def unban ip
    fw.unban ip
    store.unban ip
  end

  cmd def rm ip
    fw.unban ip
    store.rm ip
  end

  cmd def ban ip, jail = :manual
    fw.ban ip, jail if store.ban ip, jail
  end

  cmd def update # run every hour? minute?
    logger.debug "running updater"
    store.expired.each do |ban|
      unban ban
    end

    store.purge
  end

  cmd def dump
    store.dump
  end

  def start
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

  def jail_regexps = self.class.jail_regexps

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
