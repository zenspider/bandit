require "minitest/autorun"
require "bandit"
require "time"

class TestBandit < Minitest::Test
  attr_accessor :bandit
  attr_accessor :io

  def setup
    self.io      = io = StringIO.new
    self.bandit  = Bandit.new Logger.new(io, progname: "bandit")
    bandit.store = Bandit::Store::SQLiteDB.new bandit.logger, path: ":memory:"
    bandit.fw    = Bandit::FW::IpSet.new bandit.logger

    Bandit.jail_offsets.clear

    bandit.fw.singleton_class.define_method :_restore do |&b|
      b.call io
    end
  end

  def test_ban
    bandit.ban "1.2.3.4", "sanity"

    assert_includes io.string, "bandit: DB BAN sanity 1.2.3.4 count=1"
    assert_includes io.string, "bandit: FW BAN sanity 1.2.3.4"
    assert_includes io.string, "add bandit 1.2.3.4"

    data = bandit.store.db.get_first_row "SELECT * FROM bans"

    tC = Time.strptime data["created_at"], "%F %T"
    tU = Time.strptime data["updated_at"], "%F %T"
    tB = Time.strptime data["unban_at"],   "%F %T"

    assert_equal "1.2.3.4", data["ip"]
    assert_equal "sanity",  data["jail"]
    assert_equal 0,         data["allowed"]
    assert_equal 1,         data["count"]

    assert_in_delta 0,    tU - tC
    assert_in_delta 3600, tB - tC # 3600 * 2 ** 0 == 3600 (1hr)
  end

  def test_ban__offset
    Bandit.jail_offset :sanity, -3

    bandit.ban "1.2.3.4", "sanity"

    assert_includes io.string, "bandit: DB BAN sanity 1.2.3.4 count=1"
    assert_includes io.string, "bandit: FW BAN sanity 1.2.3.4"
    assert_includes io.string, "add bandit 1.2.3.4"

    data = bandit.store.db.get_first_row "SELECT * FROM bans"

    tC = Time.strptime data["created_at"], "%F %T"
    tU = Time.strptime data["updated_at"], "%F %T"
    tB = Time.strptime data["unban_at"],   "%F %T"

    assert_equal "1.2.3.4", data["ip"]
    assert_equal "sanity",  data["jail"]
    assert_equal 0,         data["allowed"]
    assert_equal 1,         data["count"]

    assert_in_delta 0,   tU - tC
    assert_in_delta 450, tB - tC # 3600 * 2 ** -3 == 450 (7.5m)
  end

  def test_ban_once
    bandit.ban "1.2.3.4"

    io.string.clear

    bandit.ban "1.2.3.4"

    assert_empty io.string
  end
end
