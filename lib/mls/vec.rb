module Melos::Vec
  extend self

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

  def from_string(str) # = to_vec
    write_varint(str.bytesize) + str
  end

  def get_prefix_and_length(str)
    prefix = str[0].ord >> 6
    length = read_varint(str)

    [prefix, length]
  end

  def parse_vec(vec_as_string)
    prefix = vec_as_string[0].ord >> 6
    length = read_varint(vec_as_string)
    case prefix
    when 0
      str = vec_as_string.byteslice(1, length)
      rest = vec_as_string.byteslice((1 + length)..)
    when 1
      str = vec_as_string.byteslice(2, length)
      rest = vec_as_string.byteslice((2 + length)..)
    when 2
      str = vec_as_string[4, length]
      rest = vec_as_string[(4 + length)..]
    else
      raise ArgumentError.new('invalid header')
    end

    [str, rest]
  end

  def get_first_vec(vec_as_string)
    prefix = vec[0].ord >> 6
    length = read_varint(vec_as_string)
    case prefix
    when 0
      first_vec = vec_as_string[0, 1 + length]
      rest = vec_as_string[(1 + length)..]
    when 1
      first_vec = vec_as_string[0, 2 + length]
      rest = vec_as_string[(2 + length)..]
    when 2
      first_vec = vec_as_string[0, 4 + length]
      rest = vec_as_string[(4 + length)..]
    else
      raise ArgumentError.new('invalid header')
    end

    [first_vec, rest]
  end
end
