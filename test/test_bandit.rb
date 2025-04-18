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

    io.string.clear # removes starting line

    Bandit.jail_offsets.clear

    bandit.fw.singleton_class.define_method :_restore do |&b|
      b.call io
    end
  end

  def test_sanity_syntax
    Dir["jails/*.rb"].sort.each do |path|
      name = File.basename(path, ".rb")
      Bandit.load_jail name
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
    create_one_ban

    bandit.ban "1.2.3.4"

    assert_empty io.string
  end

  def test_unban
    create_one_ban

    bandit.unban "1.2.3.4"

    assert_includes io.string, "bandit: DB UNBAN 1.2.3.4"
    assert_includes io.string, "bandit: FW UNBAN 1.2.3.4"
    assert_includes io.string, "del bandit 1.2.3.4"

    data = bandit.store.db.get_first_row "SELECT * FROM bans"

    assert_equal "1.2.3.4", data["ip"]
    assert_equal "sanity",  data["jail"]
    assert_equal 0,         data["allowed"]
    assert_equal 1,         data["count"]
    assert_nil              data["unban_at"]
  end

  def create_one_ban
    bandit.store.db.execute_batch <<~SQL
      DELETE FROM bans;
      INSERT INTO bans(ip, jail, count, unban_at)
           VALUES ('1.2.3.4', 'sanity', 1, datetime('now', 'localtime'));
    SQL
  end
end
