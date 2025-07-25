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

  # Adds variable length header to string, thus making it a variable length vector
  def string_to_vec(str)
    write_varint(str.bytesize) + str
  end

  # sig { params(stream: StringIO).returns(String) }
  def parse(stream)
    prefix = prefix_from_stringio(stream)
    length = length_from_stringio(stream)
    case prefix
    when 0..2
      stream.pos = (stream.pos + (2 ** prefix))
      str = stream.read(length)
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
