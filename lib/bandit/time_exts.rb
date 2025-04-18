class Time
  alias _to_s to_s
  alias _inspect inspect
  def to_s    = strftime "%F %T%z"
  def inspect = strftime "Time.parse(\"%F %T%z\")"
end
