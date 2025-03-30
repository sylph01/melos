def from_hex(hex)
  [hex].pack('H*')
end

def to_hex(bin)
  bin.unpack1('H*')
end

class String
  def to_vec
    header = []
    len = self.bytesize
    case len
    when 0..63
      header[0] = len
    when 64..16383
      header[0] = (1 << 6) || ((len & 0x3f00) >> 8)
      header[1] = len & 0x00ff
    when 16384..1073741823
      header[0] = (2 << 6) || ((len & 0x3f000000) >> 24)
      header[1] = ((len & 0x00ff0000) >> 16)
      header[2] = ((len & 0x0000ff00) >> 8)
      header[3] = len & 0x000000ff
    else
      raise ArgumentError.new('too long to be encoded in variable length vector')
    end

    header.pack('C*') + self
  end

  def self.parse_vec(vec)
    prefix = vec[0].ord >> 6
    case prefix
    when 0
      length = vec[0].ord & 0x3f
      str = vec[1, length]
      rest = vec[(1 + length)..]
    when 1
      length = (vec[0].ord & 0x3f << 8) + vec[1].ord
      str = vec[2, length]
      rest = vec[(2 + length)..]
    when 2
      length = (vec[0].ord & 0x3f << 24) + (vec[1].ord << 16) + (vec[2].ord << 8) + vec[3].ord
      str = vec[4, length]
      rest = vec[(4 + length)..]
    else
      raise ArgumentError.new('invalid header')
    end

    # puts length
    # puts to_hex(str)
    # puts to_hex(rest ? rest : '')
    [str, rest]
  end

  def self.get_first_vec(vec)
    prefix = vec[0].ord >> 6
    case prefix
    when 0
      length = vec[0].ord & 0x3f
      first_vec = vec[0, 1 + length]
      rest = vec[(1 + length)..]
    when 1
      length = (vec[0].ord & 0x3f << 8) + vec[1].ord
      first_vec = vec[0, 2 + length]
      rest = vec[(2 + length)..]
    when 2
      length = (vec[0].ord & 0x3f << 24) + (vec[1].ord << 16) + (vec[2].ord << 8) + vec[3].ord
      first_vec = vec[0, 4 + length]
      rest = vec[(4 + length)..]
    else
      raise ArgumentError.new('invalid header')
    end

    [first_vec, rest]
  end
end
