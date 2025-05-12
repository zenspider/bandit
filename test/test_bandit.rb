require "minitest/autorun"
require "bandit"

class TestBandit < Minitest::Test
  attr_accessor :bandit
  attr_accessor :io

  def setup
    self.io      = io = StringIO.new
    self.bandit  = Bandit.new Logger.new(io, progname: "bandit")
    bandit.store = Bandit::Store::SQLiteDB.new bandit.logger, path: ":memory:"
    bandit.fw    = Bandit::FW::IpSet.new bandit.logger

    bandit.fw.singleton_class.define_method :_restore do |&b|
      b.call io
    end
  end

  def test_ban
    bandit.ban "1.2.3.4"

    assert_includes io.string, "bandit: DB BAN 1.2.3.4 count=1"
    assert_includes io.string, "bandit: FW BAN 1.2.3.4"
    assert_includes io.string, "add bandit 1.2.3.4"
  end

  def test_ban_once
    bandit.ban "1.2.3.4"

    io.string.clear

    bandit.ban "1.2.3.4"

    assert_empty io.string
  end
end
