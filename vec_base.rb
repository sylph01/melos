def from_hex(hex)
  [hex].pack('H*')
end

def to_hex(bin)
  bin.unpack1('H*')
end

def read_varint(data)
  byte = 0
  v = data[byte].ord
  prefix = v >> 6
  length = 1 << prefix

  v = v & 0x3f
  (length - 1).times do
    byte += 1
    v = (v << 8) + data[byte].ord
  end

  return v
end

def write_varint(len)
  header = []
  case len
  when 0..63
    header[0] = len
  when 64..16383
    header[0] = (1 << 6) | ((len & 0x3f00) >> 8)
    header[1] = len & 0x00ff
  when 16384..1073741823
    header[0] = (2 << 6) | ((len & 0x3f000000) >> 24)
    header[1] = ((len & 0x00ff0000) >> 16)
    header[2] = ((len & 0x0000ff00) >> 8)
    header[3] = len & 0x000000ff
  else
    raise ArgumentError.new('too long to be encoded in variable length vector')
  end

  header.pack('C*')
end

class String
  def to_vec
    write_varint(self.bytesize) + self
  end

  def get_prefix_and_length
    prefix = self[0].ord >> 6
    length = read_varint(self)

    [prefix, length]
  end

  def self.parse_vec(vec)
    prefix = vec[0].ord >> 6
    length = read_varint(vec)
    case prefix
    when 0
      str = vec.byteslice(1, length)
      rest = vec.byteslice((1 + length)..)
    when 1
      str = vec.byteslice(2, length)
      rest = vec.byteslice((2 + length)..)
    when 2
      str = vec[4, length]
      rest = vec[(4 + length)..]
    else
      raise ArgumentError.new('invalid header')
    end

    [str, rest]
  end

  def self.get_first_vec(vec)
    prefix = vec[0].ord >> 6
    length = read_varint(vec)
    case prefix
    when 0
      first_vec = vec[0, 1 + length]
      rest = vec[(1 + length)..]
    when 1
      first_vec = vec[0, 2 + length]
      rest = vec[(2 + length)..]
    when 2
      first_vec = vec[0, 4 + length]
      rest = vec[(4 + length)..]
    else
      raise ArgumentError.new('invalid header')
    end

    [first_vec, rest]
  end
end
