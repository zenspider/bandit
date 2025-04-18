require_relative "bandit/time_exts"
require_relative "bandit/store"
require_relative "bandit/fw"

class Bandit
  VERSION = "1.0.0"

  HOUR       = 3_600
  DAY        = 24 * HOUR
  STALE_TIME = 28 * DAY

  attr_accessor :fw
  attr_accessor :store

  def self.commands
    public_instance_methods
      .grep(/^cmd_/)
      .sort
      .map(&:to_s)
  end

  def self.cmd(name) = alias_method "cmd_#{name}", name

  def initialize
    self.fw    = FW::Logger.new
    self.store = Store::Logger.new
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
end
