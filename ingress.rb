#!/usr/bin/env -S ruby -ws

$v ||= false

ENV["GEM_HOME"] = "tmp/isolate"
Gem.paths = ENV

require_relative "./lib/bandit"

bandit        = Bandit.new
bandit.logger = Logger.new($stderr, progname: "bandit") if $v
bandit.store  = Bandit::Store::SQLiteDB.new bandit.logger
bandit.fw     = Bandit::FW::IpSet.new bandit.logger

bandit.start

Bandit.load_jail :mail
Bandit.load_jail :apache

t0 = Time.now
stats = bandit.ingress ARGF
puts "done in #{Time.now - t0}s"

stats.sort_by { |k,v| [-v, k.inspect] }.each do |k,v|
  puts "%8d: %p" % [v, k]
end
