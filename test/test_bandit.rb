require "minitest/autorun"
require "bandit"
require "time"

class TestBandit < Minitest::Test
  attr_accessor :bandit
  attr_accessor :io
  attr_accessor :store, :db

  IP = "1.2.3.4"

  def setup
    self.io      = io = StringIO.new
    self.bandit  = Bandit.new Logger.new(io, progname: "bandit")
    bandit.store = Bandit::Store::SQLiteDB.new bandit.logger, path: ":memory:"
    bandit.fw    = Bandit::FW::IpSet.new bandit.logger
    self.store   = bandit.store
    self.db      = store.db

    io.string.clear # removes starting line

    Bandit.jail_offsets.clear

    bandit.fw.singleton_class.define_method :_restore do |&b|
      b.call io
    end
  end

  def test_sanity__syntax
    Dir["jails/*.rb"].sort.each do |path|
      name = File.basename(path, ".rb")
      Bandit.load_jail name
    end
  end

  def test_active
    db.execute_batch <<~SQL
      INSERT INTO bans(ip, jail, count, unban_at)
           VALUES ('1.2.3.4', 'sanity', 1, datetime('now', '+1 hour', 'localtime'));
      INSERT INTO bans(ip, jail, count, unban_at)
           VALUES ('1.2.3.6', 'sanity', 1, datetime('now', '-1 hour', 'localtime'));
    SQL
    store.allow IP.succ

    assert_equal [IP], store.active
  end

  def test_active__none
    assert_empty store.active
  end

  def test_allow
    store.allow IP

    assert_empty store.active

    ips = db.execute("SELECT ip FROM bans WHERE allowed").flat_map(&:values)
    assert_equal [IP], ips
  end

  def test_ban
    bandit.ban IP, "sanity"

    assert_includes io.string, "bandit: DB BAN ip=1.2.3.4 jail=sanity count=1"
    assert_includes io.string, "bandit: FW BAN ip=1.2.3.4 jail=sanity"
    assert_includes io.string, "add bandit 1.2.3.4"

    data = bans.first

    tC = Time.strptime data["created_at"], "%F %T"
    tU = Time.strptime data["updated_at"], "%F %T"
    tB = Time.strptime data["unban_at"],   "%F %T"

    assert_equal IP, data["ip"]
    assert_equal "sanity",  data["jail"]
    assert_equal 0,         data["allowed"]
    assert_equal 1,         data["count"]

    assert_in_delta 0,    tU - tC
    assert_in_delta 3600, tB - tC # 3600 * 2 ** 0 == 3600 (1hr)
  end

  def test_ban__offset
    Bandit.jail_offset :sanity, -3

    bandit.ban IP, "sanity"

    assert_includes io.string, "bandit: DB BAN ip=1.2.3.4 jail=sanity count=1"
    assert_includes io.string, "bandit: FW BAN ip=1.2.3.4 jail=sanity"
    assert_includes io.string, "add bandit 1.2.3.4"

    data = bans.first

    tC = Time.strptime data["created_at"], "%F %T"
    tU = Time.strptime data["updated_at"], "%F %T"
    tB = Time.strptime data["unban_at"],   "%F %T"

    assert_equal IP, data["ip"]
    assert_equal "sanity",  data["jail"]
    assert_equal 0,         data["allowed"]
    assert_equal 1,         data["count"]

    assert_in_delta 0,   tU - tC
    assert_in_delta 450, tB - tC # 3600 * 2 ** -3 == 450 (7.5m)
  end

  def test_ban__once
    create_one_ban

    bandit.ban IP

    assert_empty io.string
  end

  def test_expired
    db.execute_batch <<~SQL
      INSERT INTO bans(ip, jail, count, unban_at)
           VALUES ('1.2.3.4', 'sanity', 1, datetime('now', '-1 hour', 'localtime'));
      INSERT INTO bans(ip, jail, count, unban_at)
           VALUES ('1.2.3.5', 'sanity', 1, datetime('now', '+1 hour', 'localtime'));
    SQL

    assert_equal [IP], store.expired
  end

  def test_expired__none
    assert_empty store.expired
  end

  def test_next_unban__ban
    bandit.ban IP, "sanity"

    assert_in_epsilon 3600, store.next_unban
  end

  def test_next_unban__purge
    db.execute_batch <<~SQL
      INSERT INTO bans(ip, jail, count, updated_at, created_at)
           VALUES ('1.2.3.4', 'sanity', 1,
                   datetime('now', '-28 days', 'localtime'),
                   datetime('now', '-28 days', '-1 hour', 'localtime'));
    SQL

    assert_operator store.next_unban, :<, 0
  end

  def test_next_unban__both
    db.execute_batch <<~SQL
      INSERT INTO bans(ip, jail, count, updated_at, created_at)
           VALUES ('1.2.3.4', 'sanity', 1,
                   datetime('now', '-28 days', 'localtime'),
                   datetime('now', '-28 days', '-1 hour', 'localtime'));
    SQL
    bandit.ban IP.succ, "sanity"

    assert_operator store.next_unban, :<, 0
  end

  def test_purge   = skip "not yet"
  def test_report  = skip "not yet"

  def test_rm
    create_one_ban

    store.rm  IP

    assert_empty bans
  end

  def test_unban
    create_one_ban

    bandit.unban IP

    assert_includes io.string, "bandit: DB UNBAN ip=1.2.3.4"
    assert_includes io.string, "bandit: FW UNBAN ip=1.2.3.4"
    assert_includes io.string, "del bandit 1.2.3.4"

    data = bans.first

    assert_equal IP,       data["ip"]
    assert_equal "sanity", data["jail"]
    assert_equal 0,        data["allowed"]
    assert_equal 1,        data["count"]
    assert_nil             data["unban_at"]
  end

  def bans = db.execute "SELECT * FROM bans"

  def create_one_ban
    db.execute_batch <<~SQL
      INSERT INTO bans(ip, jail, count, unban_at)
           VALUES ('1.2.3.4', 'sanity', 1, datetime('now', 'localtime'));
    SQL
  end
end
