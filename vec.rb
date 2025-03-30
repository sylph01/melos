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
    context, _ = deserialize(buf)
    set_instance_vars(context)
    self
  end

  def self.new_and_rest(buf)
    instance = self.allocate
    context, buf = instance.send(:deserialize, buf)
    instance.send(:set_instance_vars, context)
    [instance, buf]
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
      when :classes
        buf += self.instance_variable_get("@#{elem[0]}").map(&:raw).join.to_vec
      when :optional
        if self.instance_variable_get("@#{elem[0]}").nil?
          buf += [0].pack('C')
        else
          buf += [1].pack('C') + self.instance_variable_get("@#{elem[0]}").raw
        end
      when :custom
        # define a custom serializer with the name "serialize_(name)"
        # which returns the serialized value of that instance variable
        buf += self.send("serialize_#{elem[0]}")
      end
    end
    buf
  end

  def self.vecs(buf)
    value, buf = String.parse_vec(buf)
    array = []
    while (value.bytesize > 0)
      current_instance, value = String.parse_vec(value)
      array << current_instance
    end
    [array, buf]
  end

  private
  def deserialize(buf)
    context = []
    self.class::STRUCT.each do |elem|
      case elem[1]
      when :uint8
        value = buf.byteslice(0, 1).unpack1('C')
        buf = buf.byteslice(1..)
        context << [elem[0], value]
      when :uint16
        value = buf.byteslice(0, 2).unpack1('S>')
        buf = buf.byteslice(2..)
        context << [elem[0], value]
      when :uint32
        value = buf.byteslice(0, 4).unpack1('L>')
        buf = buf.byteslice(4..)
        context << [elem[0], value]
      when :uint64
        value = buf.byteslice(0, 8).unpack1('Q>')
        buf = buf.byteslice(8..)
        context << [elem[0], value]
      when :vec
        value, buf = String.parse_vec(buf)
        context << [elem[0], value]
      when :vecs
        array, buf = MLSStruct::Base.vecs(buf)
        context << [elem[0], array]
      when :class
        value, buf = elem[2].send(:new_and_rest, buf)
        context << [elem[0], value]
      when :classes
        value, buf = String.parse_vec(buf)
        array = []
        while (value.bytesize > 0)
          current_instance, value = elem[2].send(:new_and_rest, value)
          array << current_instance
        end
        context << [elem[0], array]
      when :optional
        presence = buf.byteslice(0, 1).unpack1('C')
        case presence
        when 0
          value = nil
          buf.byteslice(1..)
        when 1
          # as of RFC 9420, optional always takes a class
          value, buf = elem[2].send(:new_and_rest, buf)
        end
        context << [elem[0], value]
      when :custom
        # define a custom deserializer with the name "deserialize_(name)"
        # which returns pairs of (keys and values) and the rest of the buffer
        values, buf = self.send("deserialize_#{elem[0]}", buf, context.to_h)
        context += values
      end
    end
    [context, buf]
  end

  def set_instance_vars(context)
    context.each do |elem|
      self.instance_variable_set("@#{elem[0]}", elem[1])
    end
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
  def deserialize_credential_body(buf, context)
    # cf. Section 17.5
    returns = []
    case context[:credential_type]
    when 0x0000
      # RESERVED
      raise ArgumentError.new('invalid credential type')
    when 0x0001
      # basic
      value, _ = String.parse_vec(buf)
      returns << [:identity, value]
    when 0x0002
      certificates = []
      # try parsing until buffer is blank
      value, _ = String.parse_vec(buf)
      while (value.bytesize > 0)
        current_vec, value = String.get_first_vec(value)
        certificates << MLSStruct::Certificate.new(current_vec)
      end
      returns << [:certificates, certificates]
    else
      # some values might be used for GREASE so just pass through
    end
    # this is the end of struct
    [returns, nil]
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
  def deserialize_sender_content(buf, context)
    returns = []
    case context[:sender_type]
    when 0x01
      # member
      value = buf.byteslice(0, 4).unpack1('L>')
      buf = buf.byteslice(4..)
      returns << [:leaf_index, value]
    when 0x02
      # external
      value = buf.byteslice(0, 4).unpack1('L>')
      buf = buf.byteslice(4..)
      returns << [:sender_index, value]
    when 0x03, 0x04
      # new_member_proposal, new_member_commit
    else
      # reserved, other
    end
    [returns, buf]
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
  attr_reader :group_id, :epoch, :sender, :authenticated_data, :content_type, :application_data, :proposal, :commit
  STRUCT = [
    [:group_id, :vec],
    [:epoch, :uint64],
    [:sender, :class, MLSStruct::Sender],
    [:authenticated_data, :vec],
    [:content_type, :uint8],
    [:select_content_type, :custom]
  ]

  private
  def deserialize_select_content_type(buf, context)
    returns = []
    case context[:content_type]
    when 0x01
      vec, buf = String.parse_vec(buf)
      returns << [:application_data, vec]
    when 0x02
      proposal, buf = MLSStruct::Proposal.new_and_rest(buf)
      returns << [:proposal, proposal]
    when 0x03
      commit, buf = MLSStruct::Commit.new_and_rest(buf)
      returns << [:commit, commit]
    else
    end
    [returns, buf]
  end

  def serialize_select_content_type
    case @content_type
    when 0x01
      @application_data.to_vec
    when 0x02
      @proposal.raw
    when 0x03
      @commit.raw
    else
      ''
    end
  end
end

class MLSStruct::MLSMessage < MLSStruct::Base
  attr_accessor :version, :wire_format, :public_message, :private_message, :welcome, :group_info, :key_package
  STRUCT = [
    [:version, :uint16], #mls10 = 1
    [:wire_format, :uint16],
    [:select_wire_format, :custom]
  ]

  private
  def deserialize_select_wire_format(buf, context)
    returns = []
    case context[:wire_format]
    when 0x0001 # public_message
      public_message, buf = MLSStruct::PublicMessage.new_and_rest(buf)
      returns << [:public_message, public_message]
    when 0x0002 # private_message
      private_message, buf = MLSStruct::PrivateMessage.new_and_rest(buf)
      returns << [:private_message, private_message]
    when 0x0003 # welcome
      welcome, buf = MLSStruct::Welcome.new_and_rest(buf)
      returns << [:welcome, welcome]
    when 0x0004 # mls_group_info
      group_info, buf = MLSStruct::GroupInfo.new_and_rest(buf)
      returns << [:group_info, group_info]
    when 0x0005 # mls_key_package
      key_package, buf = MLSStruct::KeyPackage.new_and_rest(buf)
      returns << [:key_package, key_package]
    else
    end
  end

  def serialize_select_wire_format
    case @wire_format
    when 0x0001
      @public_message.raw
    when 0x0002
      @private_message.raw
    when 0x0003
      @welcome.raw
    when 0x0004
      @group_info.raw
    when 0x0005
      @key_package.raw
    else
    end
  end
end

class MLSStruct::FramedContentTBS < MLSStruct::Base
  attr_reader :version, :wire_format, :content, :context
  STRUCT = [
    [:version, :uint16], #mls10 = 1
    [:wire_format, :uint16],
    [:content, :class, MLSStruct::FramedContent],
    [:select_sender_type, :custom]
  ]

  private
  def deserialize_select_sender_type(buf, context)
    returns = []
    case context[:content].sender.sender_type
    when 0x01, 0x04 #member, new_member_commit
      group_context, buf = MLSStruct::GroupContext.new_and_rest(buf)
      returns << [:context, group_context]
    when 0x02, 0x03 #external, new_member_proposal
      # add an empty struct, aka nothing
    else
      # add nothing
    end
    [returns, buf]
  end

  def serialize_select_sender_type
    case @content.sender.sender_type
    when 0x01, 0x04
      @context.raw
    when 0x02, 0x03
      ''
    else
      ''
    end
  end
end

class MLSStruct::FramedContentAuthData
  # construct from FramedContent instead of raw binary
  def initialize(wire_format, framed_content)
    data_to_be_signed = [[0x01].pack('S>'), [wire_format].pack('S>'), framed_content.raw].join
    @framed_content_tbs = MLSStruct::FramedContentTBS.new(data_to_be_signed) # when creating this, we might need group context too

    @signature = @framed_content_tbs.raw # will use cipher suite later to sign
    case framed_content.content_type
    when 0x03
      # MAC(confirmation_key, GroupContext.confirmed_transcript_hash)
      # where do these two values come from?
      @confirmation_tag = @framed_content_tbs.group_context.confirmed_transcript_hash
    when 0x01, 0x02
      # empty struct, thus do nothing
    else
    end
  end

  def raw
    case framed_content.content_type
    when 0x03
      @signature.to_vec + @confirmation_tag.to_vec
    when 0x01, 0x02
      @signature.to_vec
    else
      ''
    end
  end
end


class MLSStruct::AuthenticatedContent
  # construct from WireFormat and FramedContent
  def initialize(wire_format, framed_content)
    @wire_format = wire_format
    @content = framed_content
    @auth = MLSStruct::FramedContentAuthData.new(wire_format, framed_content)
  end

  def raw
    [
      [@wire_format].pack('S>'),
      @content.raw,
      @auth.raw
    ].join
  end
end

# random
class MLSStruct::Hoge < MLSStruct::Base
  attr_reader :optional
  STRUCT = [
    [:optional, :vec]
  ]
end

class MLSStruct::Klass < MLSStruct::Base
  attr_reader :hoge, :hoge2
  STRUCT = [
    [:hoge, :class, MLSStruct::Hoge],
    [:hoge2, :class, MLSStruct::Hoge]
  ]
end

class MLSStruct::Klasses < MLSStruct::Base
  attr_reader :hoges
  STRUCT = [
    [:hoges, :classes, MLSStruct::Hoge]
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
