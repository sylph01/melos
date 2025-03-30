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
      when :select
        value = self.instance_variable_get("@#{elem[0]}")
        buf += serialize_select_elem(value, elem[3])
      else
        value = self.instance_variable_get("@#{elem[0]}")
        buf += serialize_elem(value, elem[1])
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

  # context here takes a hash
  # returns [value, rest_of_buffer]
  # value could return nil, which means predicate was not applicable
  # predicate takes the context and returns true or false
  def deserialize_select_elem_with_context(buf, context, predicate, type, type_param)
    if predicate.(context)
      deserialize_elem(buf, type, type_param)
    else
      [nil, buf]
    end
  end

  private
  def deserialize(buf)
    context = []
    self.class::STRUCT.each do |elem|
      case elem[1]
      when :select
        value, buf = deserialize_select_elem_with_context(buf, context.to_h, elem[2], elem[3], elem[4])
        context << [elem[0], value]
      else
        value, buf = deserialize_elem(buf, elem[1], elem[2])
        context << [elem[0], value]
      end
    end
    [context, buf]
  end

  def set_instance_vars(context)
    context.each do |elem|
      self.instance_variable_set("@#{elem[0]}", elem[1])
    end
  end

  def deserialize_elem(buf, type, type_param)
    case type
    when :uint8
      value = buf.byteslice(0, 1).unpack1('C')
      buf = buf.byteslice(1..)
    when :uint16
      value = buf.byteslice(0, 2).unpack1('S>')
      buf = buf.byteslice(2..)
    when :uint32
      value = buf.byteslice(0, 4).unpack1('L>')
      buf = buf.byteslice(4..)
    when :uint64
      value = buf.byteslice(0, 8).unpack1('Q>')
      buf = buf.byteslice(8..)
    when :vec
      value, buf = String.parse_vec(buf)
    when :vecs
      value, buf = MLSStruct::Base.vecs(buf)
    when :class
      value, buf = type_param.send(:new_and_rest, buf)
    when :classes
      vec, buf = String.parse_vec(buf)
      value = []
      while (vec.bytesize > 0)
        current_instance, vec = type_param.send(:new_and_rest, vec)
        value << current_instance
      end
    when :optional
      presence = buf.byteslice(0, 1).unpack1('C')
      case presence
      when 0
        value = nil
        buf = buf.byteslice(1..)
      when 1
        # as of RFC 9420, optional always takes a class
        value, buf = elem[2].send(:new_and_rest, buf)
      end
    when :opaque
      value = buf.byteslice(0, type_param.to_i)
      buf = buf.byteslice((type_param.to_i)..)
    end
    [value, buf]
  end

  # take a name and type
  def serialize_elem(value, type)
    case type
    when :uint8
      [value].pack('C')
    when :uint16
      [value].pack('S>')
    when :uint32
      [value].pack('L>')
    when :uint64
      [value].pack('Q>')
    when :vec
      value.to_vec
    when :vecs
      value.map(&:to_vec).join.to_vec
    when :class
      value.raw
    when :classes
      value.map(&:raw).join.to_vec
    when :optional
      if value.nil?
        [0].pack('C')
      else
        # as of RFC 9420, optional always takes a class
        [1].pack('C') + value.raw
      end
    when :opaque
      value
    end
  end

  def serialize_select_elem(value, type)
    if value.nil?
      ''
    else
      serialize_elem(value, type)
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
    [:identity,     :select, ->(ctx){ctx[:credential_type] == 0x0001}, :vec], # 0x0001 = basic
    [:certificates, :select, ->(ctx){ctx[:credential_type] == 0x0002}, :classes, MLSStruct::Certificate] #0x0002 = x509
  ]
end

# Section 6.1
class MLSStruct::Sender < MLSStruct::Base
  attr_reader :sender_type, :leaf_index, :sender_index
  STRUCT = [
    [:sender_type, :uint8],
    [:leaf_index,   :select, ->(ctx){ctx[:sender_type] == 0x01}, :uint32], # 0x01 = member
    [:sender_index, :select, ->(ctx){ctx[:sender_type] == 0x02}, :uint32], # 0x02 = external
  ]
end

class MLSStruct::FramedContent < MLSStruct::Base
  attr_reader :group_id, :epoch, :sender, :authenticated_data, :content_type, :application_data, :proposal, :commit
  STRUCT = [
    [:group_id, :vec],
    [:epoch, :uint64],
    [:sender, :class, MLSStruct::Sender],
    [:authenticated_data, :vec],
    [:content_type, :uint8],
    [:application_data, :select, ->(context){context[:content_type] == 0x01}, :vec],
    #[:proposal,         :select, ->(context){context[:content_type] == 0x02}, :class, MLSStruct::Proposal],
    #[:commit,           :select, ->(context){context[:content_type] == 0x03}, :class, MLSStruct::Commit]
  ]
end

class MLSStruct::MLSMessage < MLSStruct::Base
  attr_accessor :version, :wire_format, :public_message, :private_message, :welcome, :group_info, :key_package
  STRUCT = [
    [:version, :uint16], #mls10 = 1
    [:wire_format, :uint16],
    # [:public_message,  :select, ->(ctx){ctx[:wire_format] == 0x0001}, :class, MLSStruct::PublicMessage],
    # [:private_message, :select, ->(ctx){ctx[:wire_format] == 0x0002}, :class, MLSStruct::PrivateMessage],
    # [:welcome,         :select, ->(ctx){ctx[:wire_format] == 0x0003}, :class, MLSStruct::Welcome],
    # [:group_info,      :select, ->(ctx){ctx[:wire_format] == 0x0004}, :class, MLSStruct::GroupInfo],
    # [:key_package,     :select, ->(ctx){ctx[:wire_format] == 0x0005}, :class, MLSStruct::KeyPackage]
  ]
end

class MLSStruct::FramedContentTBS < MLSStruct::Base
  attr_reader :version, :wire_format, :content, :context
  STRUCT = [
    [:version, :uint16], #mls10 = 1
    [:wire_format, :uint16],
    [:content, :class, MLSStruct::FramedContent],
    # [:context, :select, ->(ctx){[0x01, 0x04].include?(ctx[:content].sender.sender_type)}, :class, MLSStruct::GroupContext]
  ]
end

class MLSStruct::FramedContentAuthData; end

# class MLSStruct::FramedContentAuthData < MLSStruct::Base
#   attr_accessor :content_type
#   attr_reader :signature, :confirmation_tag
#   STRUCT = [
#     [:signature, :vec], # SignWithLabel(., "FramedContentTBS", FramedContentTBS)
#     [:select_content_type, :custom]
#   ]

#   private
#   def deserialize_select_content_type(buf, context)
#     returns = []
#     case @content_type
#     when 0x03 # commit
#       mac, buf = String.parse_vec(buf) # MAC(confirmation_key, GroupContext.confirmed_transcript_hash)
#       returns << [:confirmation_tag, mac]
#     else
#       # add nothing
#     end
#     [returns, buf]
#   end

#   def serialize_select_content_type
#     case @content_type
#     when 0x03 # commit
#       @confirmation_tag.to_vec
#     else
#       ''
#     end
#   end
# end

# class MLSStruct::FramedContentAuthData
#   # construct from FramedContent instead of raw binary
#   def initialize(wire_format, framed_content)
#     data_to_be_signed = [[0x01].pack('S>'), [wire_format].pack('S>'), framed_content.raw].join
#     @framed_content_tbs = MLSStruct::FramedContentTBS.new(data_to_be_signed) # when creating this, we might need group context too

#     @signature = @framed_content_tbs.raw # will use cipher suite later to sign
#     case framed_content.content_type
#     when 0x03
#       # MAC(confirmation_key, GroupContext.confirmed_transcript_hash)
#       # where do these two values come from?
#       @confirmation_tag = @framed_content_tbs.group_context.confirmed_transcript_hash
#     when 0x01, 0x02
#       # empty struct, thus do nothing
#     else
#     end
#   end

#   def raw
#     case framed_content.content_type
#     when 0x03
#       @signature.to_vec + @confirmation_tag.to_vec
#     when 0x01, 0x02
#       @signature.to_vec
#     else
#       ''
#     end
#   end
# end


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

## 6.2

class MLSStruct::PublicMessage < MLSStruct::Base
  attr_reader :content, :auth, :membership_tag
  STRUCT = [
    [:content, :class, MLSStruct::FramedContent],
    [:auth, :class, MLSStruct::FramedContentAuthData],
    [:membership_tag, :select, ->(ctx){ctx[:content].sender.sender_type == 0x01}, :vec] # mmeber; MAC is opaque <V>
  ]
end

class MLSStruct::AuthenticatedContentTBM < MLSStruct::Base
  attr_reader :content_tbs, :auth
  STRUCT = [
    [:content_tbs, :class, MLSStruct::FramedContentTBS],
    [:auth, :class, MLSStruct::FramedContentAuthData]
  ]
end

## 6.3

class MLSStruct::PrivateMessage < MLSStruct::Base
  attr_reader :group_id, :epoch, :content_type, :authenticated_data, :encrypted_sender_data, :ciphertext
  STRUCT = [
    [:group_id, :vec],
    [:epoch, :uint64],
    [:content_type, :uint8],
    [:authenticated_data, :vec],
    [:encrypted_sender_data, :vec],
    [:ciphertext, :vec]
  ]
end

class MLSStruct::PrivateMessageContent
  # bytes -> struct: decode the content and auth field, rest is padding
  # struct -> bytes: encode content and auth field, add set amount of padding (zero bytes)
end

class MLSStruct::PrivateContentAAD
  attr_reader :group_id, :epoch, :content_type, :authenticated_data
  STRUCT = [
    [:group_id, :vec],
    [:epoch, :uint64],
    [:content_type, :uint8],
    [:authenticated_data, :vec]
  ]
end

## 6.3.2

class MLSStruct::SenderData < MLSStruct::Base
  attr_reader :leaf_index, :generation, :reuse_guard
  STRUCT = [
    [:leaf_index, :uint32],
    [:generation, :uint32],
    [:reuse_guard, :opaque, 4]
  ]
end

class MLSStruct::SenderDataAAD < MLSStruct::Base
  attr_reader :group_id, :epoch, :content_type
  STRUCT = [
    [:group_id, :vec],
    [:epoch, :uint64],
    [:content_type, :uint8]
  ]
end

## 7.1

class MLSStruct::ParentNode < MLSStruct::Base
  attr_reader :encryption_key, :parent_hash, :unmerged_leaves
  STRUCT = [
    [:encryption_key, :vec], # HPKEPublicKey = opaque <V>
    [:parent_hash, :vec],
    [:unmerged_leaves, :vec] # becomes a vec of uint32
  ]
end

## 7.2

class MLSStruct::Capabilities < MLSStruct::Base
  attr_reader :versions, :cipher_suites, :extensions, :proposals, :credentials
  STRUCT = [
    [:versions, :vec],      # vec of ProtocolVersion (uint16)
    [:cipher_suites, :vec], # vec of CipherSuite (uint16)
    [:extensions, :vec],    # vec of ExtensionType (uint16)
    [:proposals, :vec],     # vec of ProposalTypes (uint16)
    [:credentials, :vec]    # vec of CredentialTypes (uint16)
  ]
end

class MLSStruct::Lifetime < MLSStruct::Base
  attr_reader :not_before, :not_after
  STRUCT = [
    [:not_before, :uint64],
    [:not_after, :uint64]
  ]
end

class MLSStruct::Extension < MLSStruct::Base
  attr_reader :extension_type, :extension_data
  STRUCT = [
    [:extension_type, :uint16], # ExtensionType = uint16
    [:extension_data, :vec]
  ]
end

class MLSStruct::LeafNode < MLSStruct::Base
  attr_reader :encryption_key, :signature_key, :credential, :capabilities, :leaf_node_source, :lifetime, :parent_hash, :extensions, :signature
  STRUCT = [
    [:encryption_key, :vec], # HPKEPublicKey = opaque <V>
    [:signature_key, :vec],  # SignaturePublicKey = opaque <V>
    [:credential, :class, MLSStruct::Credential],
    [:capabilities, :class, MLSStruct::Capabilities],
    [:leaf_node_source, :uint8], # LeafNodeSource = enum of uint8,
    [:lifetime, :select,    ->(ctx){ctx[:leaf_node_source] == 0x01}, :class, MLSStruct::Lifetime], # key_package
    [:parent_hash, :select, ->(ctx){ctx[:leaf_node_source] == 0x03}, :vec],                        # commit
    [:select_leaf_node_source, :custom],
    [:extensions, :classes, MLSStruct::Extension],
    [:signature, :vec]
  ]
end

class MLSStruct::LeafNodeTBS < MLSStruct::Base
  attr_reader :encryption_key, :signature_key, :credential, :capabilities, :leaf_node_source, :lifetime, :parent_hash, :extensions, :group_id, :leaf_index
  STRUCT = [
    [:encryption_key, :vec], # HPKEPublicKey = opaque <V>
    [:signature_key, :vec],  # SignaturePublicKey = opaque <V>
    [:credential, :class, MLSStruct::Credential],
    [:capabilities, :class, MLSStruct::Capabilities],
    [:leaf_node_source, :uint8], # LeafNodeSource = enum of uint8,
    [:select_leaf_node_source, :custom],
    [:extensions, :vec],
    [:select_leaf_node_source_2, :custom]
  ]

  private
  def deserialize_select_leaf_node_source(buf, context)
    returns = []
    case context[:leaf_node_source]
    when 0x01 # key_package
      lifetime, buf = MLSStruct::Lifetime.new_and_rest(buf)
      returns << [:lifetime, lifetime]
    when 0x02 # update
      # add an empty struct, aka nothing
    when 0x03 # commit
      parent_hash, buf = String.parse_vec(buf)
      returns << [:parent_hash, parent_hash]
    else
      # add nothing
    end
    [returns, buf]
  end

  def deserialize_select_leaf_node_source_2(buf, context)
    returns = []
    case context[:leaf_node_source]
    when 0x01 # key_package
      # add an empty struct, aka nothing
    when 0x02, 0x03 # update, commit
      group_id, buf = String.parse_vec(buf)
      returns << [:group_id, group_id]
      leaf_index = buf.byteslice(0, 4).unpack1('L>') # uint32
      buf = buf.byteslice(4..)
      returns << [:leaf_index, leaf_index]
    else
      # add nothing
    end
    [returns, buf]
  end

  def serialize_select_leaf_node_source
    case @leaf_node_source
    when 0x01
      @lifetime.raw
    when 0x02
      ''
    when 0x03
      @parent_hash.to_vec
    else
      ''
    end
  end

  def serialize_select_leaf_node_source_2
    case @leaf_node_source
    when 0x01
      ''
    when 0x02, 0x03
      @group_id.to_vec + [@leaf_index].pack('L>')
    else
      ''
    end
  end
end

## 7.6

class MLSStruct::HPKECipherText < MLSStruct::Base
  attr_reader :kem_output, :ciphertext
  STRUCT = [
    [:kem_output, :vec],
    [:ciphertext, :vec]
  ]
end

class MLSStruct::UpdatePathNode < MLSStruct::Base
  attr_reader :encryption_key, :encrypted_path_secret
  STRUCT = [
    [:encryption_key, :vec], # HPKEPublicKey = opaque <V>
    [:encrypted_path_secret, :classes, MLSStruct::HPKECipherText]
  ]
end

class MLSStruct::UpdatePath < MLSStruct::Base
  attr_reader :leaf_node, :nodes
  STRUCT = [
    [:leaf_node, :class, MLSStruct::LeafNode],
    [:nodes, :classes, MLSStruct::UpdatePathNode]
  ]
end

## 7.8

## NodeType: uint8 enum

class MLSStruct::LeafNodeHashInput < MLSStruct::Base
  attr_reader :leaf_index, :leaf_node
  STRUCT = [
    [:leaf_index, :uint32],
    [:leaf_node, :optional, MLSStruct::LeafNode]
  ]
end

class MLSStruct::ParentNodeHashInput < MLSStruct::Base
  attr_reader :parent_node, :left_hash, :right_hash
  STRUCT = [
    [:parent_node, :optional, MLSStruct::ParentNode],
    [:left_hash, :vec],
    [:right_hash, :vec]
  ]
end

## 7.9

class MLSStruct::ParentHashInput < MLSStruct::Base
  attr_reader :encryption_key, :parent_hash, :original_sibling_tree_hash
  STRUCT = [
    [:encryption_key, :vec], # HPKEPublicKey
    [:parent_hash, :vec],
    [:original_sibling_tree_hash, :vec]
  ]
end

class MLSStruct::TreeHashInput < MLSStruct::Base
  attr_reader :node_type, :leaf_node, :parent_node
  STRUCT = [
    [:node_type, :uint8],
    [:leaf_node,   :select, ->(ctx){ctx[:node_type] == 0x01}, :class, MLSStruct::LeafNodeHashInput],   # key_package
    [:parent_node, :select, ->(ctx){ctx[:node_type] == 0x02}, :class, MLSStruct::ParentNodeHashInput], # update
  ]
end

## 8

class MLSStruct::KDFLabel < MLSStruct::Base
  attr_reader :length, :label, :context
  STRUCT = [
    [:length, :uint16],
    [:label, :vec],
    [:context, :vec]
  ]
end

## 8.1

class MLSStruct::GroupContext < MLSStruct::Base
  attr_reader :version, :cipher_suite, :group_id, :epoch, :tree_hash, :confirmed_transcript_hash, :extensions
  STRUCT = [
    [:version, :uint16],
    [:cipher_suite, :uint16],
    [:group_id, :vec],
    [:epoch, :uint64],
    [:tree_hash, :vec],
    [:confirmed_transcript_hash, :vec],
    [:extensions, :classes, MLSStruct::Extension]
  ]
end

## 8.2

class MLSStruct::ConfirmedTranscriptHash < MLSStruct::Base
  attr_reader :wire_format, :content, :signature
  STRUCT = [
    [:wire_format, :uint16],
    [:content, :class, MLSStruct::FramedContent], # with content_type == commit
    [:signature, :vec]
  ]
end

class MLSStruct::InterimTranscriptHashInput < MLSStruct::Base
  attr_reader :confirmation_tag
  STRUCT = [
    [:confirmation_tag, :vec]
  ]
end

## 8.4

class MLSStruct::PreSharedKeyID < MLSStruct::Base
  attr_reader :psktype, :psk_id, :psk_group_id, :psk_epoch, :psk_nonce
  STRUCT = [
    [:psktype, :uint8],
    [:psk_id,       :select, ->(ctx){ctx[:psktype] == 0x01}, :vec],    # external
    [:psk_group_id, :select, ->(ctx){ctx[:psktype] == 0x02}, :vec],    # resumption
    [:psk_epoch,    :select, ->(ctx){ctx[:psktype] == 0x02}, :uint64], # resumption
    [:psk_nonce, :vec]
  ]
end

class MLSStruct::PSKLabel < MLSStruct::Base
  attr_reader :id, :index, :count
  STRUCT = [
    [:id, :class, MLSStruct::PreSharedKeyID],
    [:index, :uint16],
    [:count, :uint16]
  ]
end

## 10

class MLSStruct::KeyPackage < MLSStruct::Base
  attr_reader :version, :cipher_suite, :init_key, :leaf_node, :extensions, :signature
  STRUCT = [
    [:version, :uint16],
    [:cipher_suite, :uint16],
    [:init_key, :vec], # HPKEPublicKey
    [:leaf_node, :class, MLSStruct::LeafNode],
    [:extensions, :classes, MLSStruct::Extension],
    [:signature, :vec] # SignWithLabel(., "KeyPackageTBS", KeyPackageTBS)
  ]
end

class MLSStruct::KeyPackageTBS < MLSStruct::Base
  attr_reader :version, :cipher_suite, :init_key, :leaf_node, :extensions
  STRUCT = [
    [:version, :uint16],
    [:cipher_suite, :uint16],
    [:init_key, :vec], # HPKEPublicKey
    [:leaf_node, :class, MLSStruct::LeafNode],
    [:extensions, :classes, MLSStruct::Extension]
  ]
end

## 11

class MLSStruct::RequiredCapabilities < MLSStruct::Base
  attr_reader :extension_types, :proposal_types, :credential_types
  STRUCT = [
    [:extension_types, :vec], # vec of uint16
    [:proposal_types, :vec], # vec of uint16
    [:credential_types, :vec] # vec of uint16
  ]
end

# 12.4.3.1

class MLSStruct::PathSecret < MLSStruct::Base
  attr_reader :path_secret
  STRUCT = [
    [:path_secret, :vec]
  ]
end

### ---------------------------------------------------------------------- ###

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
