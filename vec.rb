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

module MLSStruct; end

class MLSStruct::Base
  def initialize(buf)
    self.class::STRUCT.each do |elem|
      case elem[1]
      when :uint8
        value = buf.byteslice(0, 1).unpack1('C')
        self.instance_variable_set("@#{elem[0]}", value)
        buf = buf.byteslice(1..)
      when :uint16
        value = buf.byteslice(0, 2).unpack1('S>')
        self.instance_variable_set("@#{elem[0]}", value)
        buf = buf.byteslice(2..)
      when :uint32
        value = buf.byteslice(0, 4).unpack1('L>')
        self.instance_variable_set("@#{elem[0]}", value)
        buf = buf.byteslice(4..)
      when :uint64
        value = buf.byteslice(0, 8).unpack1('Q>')
        self.instance_variable_set("@#{elem[0]}", value)
        buf = buf.byteslice(8..)
      when :vec
        value, buf = String.parse_vec(buf)
        self.instance_variable_set("@#{elem[0]}", value)
      when :vecs
        value, buf = String.parse_vec(buf)
        array = []
        while (value.bytesize > 0)
          current_vec, value = String.parse_vec(value)
          array << current_vec
        end
        self.instance_variable_set("@#{elem[0]}", array)
      when :class
        vec, buf = String.get_first_vec(buf)
        self.instance_variable_set("@#{elem[0]}", elem[2].send(:new, vec))
      when :custom
        # define a custom deserializer with the name "initialize_(name)"
        # which returns the rest of the buffer
        buf = self.send("initialize_#{elem[0]}", buf)
      end
    end
  end

  def raw
    buf = ''
    self.class::STRUCT.each do |elem|
      case elem[1]
      when :uint8
        buf += [self.instance_variable_get("@#{elem[0]}")].pack('C')
      when :uint16
        buf += [self.instance_variable_get("@#{elem[0]}")].pack('S>')
      when :uint32
        buf += [self.instance_variable_get("@#{elem[0]}")].pack('L>')
      when :uint64
        buf += [self.instance_variable_get("@#{elem[0]}")].pack('Q>')
      when :vec
        buf += self.instance_variable_get("@#{elem[0]}").to_vec
      when :vecs
        buf += self.instance_variable_get("@#{elem[0]}").map(&:to_vec).join.to_vec
      when :class
        buf += self.instance_variable_get("@#{elem[0]}").raw
      when :custom
        # define a custom serializer with the name "serialize_(name)"
        # which returns the serialized value of that instance variable
        buf += self.send("serialize_#{elem[0]}")
      end
    end
    buf
  end
end

class MLSStruct::EncryptContext < MLSStruct::Base
  attr_reader :label, :context
  STRUCT = [
    [:label, :vec],
    [:context, :vec]
  ]
end

class MLSStruct::RefHashInput < MLSStruct::Base
  attr_reader :label, :value
  STRUCT = [
    [:label, :vec],
    [:value, :vec]
  ]
end

# Section 5.3 Credentials
class MLSStruct::Certificate < MLSStruct::Base
  attr_reader :cert_data
  STRUCT = [
    [:cert_data, :vec]
  ]
end

class MLSStruct::Credential < MLSStruct::Base
  attr_reader :credential_type, :identity, :certificates
  STRUCT = [
    [:credential_type, :uint16],
    [:credential_body, :custom]
  ]

  private
  def initialize_credential_body(buf)
    # cf. Section 17.5
    case @credential_type
    when 0x0000
      # RESERVED
      raise ArgumentError.new('invalid credential type')
    when 0x0001
      # basic
      value, _ = String.parse_vec(buf)
      @identity = value
    when 0x0002
      @certificates = []
      # try parsing until buffer is blank
      value, _ = String.parse_vec(buf)
      while (value.bytesize > 0)
        current_vec, value = String.get_first_vec(value)
        @certificates << MLSStruct::Certificate.new(current_vec)
      end
    else
      # some values might be used for GREASE so just pass through
    end
    # this is the end of struct
    nil
  end

  def serialize_credential_body
    case @credential_type
    when 0x0001
      @identity.to_vec
    when 0x0002
      @certificates.map(&:raw).reduce(&:+).to_vec
    else
      # should not happen?
      ''
    end
  end
end

# Section 6.1
class MLSStruct::Sender < MLSStruct::Base
  attr_reader :sender_type, :leaf_index, :sender_index
  STRUCT = [
    [:sender_type, :uint8],
    [:sender_content, :custom],
  ]

  private
  def initialize_sender_content(buf)
    case @sender_type
    when 0x01
      # member
      value = buf.byteslice(0, 4).unpack1('L>')
      @leaf_index = value
    when 0x02
      # external
      value = buf.byteslice(0, 4).unpack1('L>')
      @sender_index = value
    when 0x03, 0x04
      # new_member_proposal, new_member_commit
      ''
    else
      # reserved, other
      ''
    end
    nil # end of buffer
  end

  def serialize_sender_content
    case @sender_type
    when 0x01
      # member
      [@leaf_index].pack('L>')
    when 0x02
      # external
      [@sender_index].pack('L>')
    when 0x03, 0x04
      # new_member_proposal, new_member_commit
      ''
    else
      # reserved, other
      ''
    end
  end
end

class MLSStruct::FramedContent < MLSStruct::Base

end

# random
class MLSStruct::Hoge < MLSStruct::Base
  attr_reader :optional
  STRUCT = [
    [:optional, :vec]
  ]
end

class MLSStruct::Klass < MLSStruct::Base
  attr_reader :hoge
  STRUCT = [
    [:hoge, :class, MLSStruct::Hoge]
  ]
end

class MLSStruct::Hoge2 < MLSStruct::Base
  attr_reader :optional, :optional2, :vector
  STRUCT = [
    [:optional, :uint16],
    [:optional2, :custom],
    [:vector, :vec]
  ]

  private
  def initialize_optional2(buf)
    value = buf.byteslice(0, 2).unpack1('S>')
    self.instance_variable_set("@optional2", value)
    buf.byteslice(2..)
  end

  def serialize_optional2
    [self.instance_variable_get("@optional2")].pack('S>')
  end
end

class MLSStruct::Vecs < MLSStruct::Base
    attr_reader :vecs
  STRUCT = [
    [:vecs, :vecs]
  ]
end
