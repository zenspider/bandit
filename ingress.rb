#!/usr/bin/env -S ruby -ws

$v ||= false # verbose, log to standard out
$t ||= false # test mode, use test.db

ENV["GEM_HOME"] = "tmp/isolate"
Gem.paths = ENV

require_relative "./lib/bandit"

store_opts = { path: "test.db" } if $t

bandit        = Bandit.new
bandit.logger = Logger.new($stderr, progname: "bandit") if $v
bandit.store  = Bandit::Store::SQLiteDB.new bandit.logger, **store_opts
bandit.fw     = Bandit::FW::IpSet.new bandit.logger unless $t

bandit.start

Bandit.load_jail :mail
Bandit.load_jail :apache404
Bandit.load_jail :sshd
Bandit.load_jail :dovecot

t0 = Time.now
stats = bandit.ingress ARGF
puts "done in #{Time.now - t0}s"

stats.sort_by { |k,v| [-v, k.inspect] }.each do |k,v|
  puts "%8d: %p" % [v, k]
end
