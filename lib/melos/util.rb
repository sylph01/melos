module Melos::Util
  extend self

  def from_hex(hex)
    [hex].pack('H*')
  end

  def to_hex(bin)
    bin.unpack1('H*')
  end
end
