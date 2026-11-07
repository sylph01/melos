module Melos::Vec
  extend self

  def read_varint(data)
    raise ArgumentError.new('variable-length vector is truncated') if data.nil? || data.empty?
    byte = 0
    v = data[byte].ord
    prefix = v >> 6
    length = 1 << prefix

    v = v & 0x3f
    (length - 1).times do
      byte += 1
      raise ArgumentError.new('variable-length vector is truncated') if data[byte].nil?
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
  def parse_stream(stream)
    prefix = prefix_from_stream(stream)
    raise ArgumentError.new('invalid header') unless (0..2).include?(prefix) # 2.1.2: prefix 3 is invalid
    header_length = 2 ** prefix
    length = length_from_stream(stream)
    # 2.1.2: the length MUST be encoded in the minimum number of bytes; a longer encoding is rejected
    raise ArgumentError.new('variable-length header is not minimal') unless write_varint(length).bytesize == header_length
    stream.pos += header_length
    str = stream.read(length) || ''
    raise ArgumentError.new('variable-length vector is truncated') if str.bytesize < length
    str
  end

  private

  def prefix_from_stream(stringio)
    pos = stringio.pos
    first = stringio.getbyte
    raise ArgumentError.new('variable-length vector is truncated') if first.nil?
    prefix_ = first >> 6
    stringio.seek(pos)
    prefix_
  end

  def length_from_stream(stringio)
    pos = stringio.pos
    buf = stringio.read(4)
    stringio.seek(pos)
    read_varint(buf)
  end
end
