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

  def parse_stringio(vec_as_stringio)
    prefix = prefix_from_stringio(vec_as_stringio)
    length = length_from_stringio(vec_as_stringio)
    case prefix
    when 0..2
      vec_as_stringio.pos = (vec_as_stringio.pos + (2 ** prefix))
      str = vec_as_stringio.read(length)
    else
      raise ArgumentError.new('invalid header')
    end

    str
  end

  private

  def prefix_from_stringio(stringio)
    pos = stringio.pos
    prefix_ = stringio.getbyte >> 6
    stringio.seek(pos)
    prefix_
  end

  def length_from_stringio(stringio)
    pos = stringio.pos
    buf = stringio.read(4)
    stringio.seek(pos)
    read_varint(buf)
  end
end
