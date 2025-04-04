require_relative 'vec_base.rb'
require_relative 'mls_struct_base.rb'

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

  def self.create(cipher_suite:, group_id:, epoch:, tree_hash:, confirmed_transcript_hash:, extensions:)
    new_instance = self.allocate
    new_instance.instance_variable_set(:@version, 1)
    new_instance.instance_variable_set(:@cipher_suite, cipher_suite)
    new_instance.instance_variable_set(:@group_id, group_id)
    new_instance.instance_variable_set(:@epoch, epoch)
    new_instance.instance_variable_set(:@tree_hash, tree_hash)
    new_instance.instance_variable_set(:@confirmed_transcript_hash, confirmed_transcript_hash)
    new_instance.instance_variable_set(:@extensions, extensions)
    new_instance
  end
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

  def self.create_external(psk_id:, psk_nonce:)
    new_instance = self.allocate
    new_instance.instance_variable_set(:@psktype, 0x01)
    new_instance.instance_variable_set(:@psk_id, psk_id)
    new_instance.instance_variable_set(:@psk_nonce, psk_nonce)
    new_instance
  end
end

class MLSStruct::PSKLabel < MLSStruct::Base
  attr_reader :id, :index, :count
  STRUCT = [
    [:id, :class, MLSStruct::PreSharedKeyID],
    [:index, :uint16],
    [:count, :uint16]
  ]

  def self.create(id:, index:, count:)
    new_instance = self.allocate
    new_instance.instance_variable_set(:@id, id)
    new_instance.instance_variable_set(:@index, index)
    new_instance.instance_variable_set(:@count, count)
    new_instance
  end
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

## 12

## 12.1.1 - 12.1.7

class MLSStruct::Add < MLSStruct::Base
  attr_reader :key_package
  STRUCT = [
    [:key_package, :class, MLSStruct::KeyPackage]
  ]
end

class MLSStruct::Update < MLSStruct::Base
  attr_reader :leaf_node
  STRUCT = [
    [:leaf_node, :class, MLSStruct::LeafNode]
  ]
end

class MLSStruct::Remove < MLSStruct::Base
  attr_reader :removed
  STRUCT = [
    [:removed, :uint32]
  ]
end

class MLSStruct::PreSharedKey < MLSStruct::Base
  attr_reader :psk
  STRUCT = [
    [:psk, :class, MLSStruct::PreSharedKeyID]
  ]
end

class MLSStruct::ReInit < MLSStruct::Base
  attr_reader :group_id, :version, :cipher_suite, :extensions
  STRUCT = [
    [:group_id, :vec],
    [:version, :uint16],
    [:cipher_suite, :uint16],
    [:extensions, :classes, MLSStruct::Extension]
  ]
end

class MLSStruct::ExternalInit < MLSStruct::Base
  attr_reader :kem_output
  STRUCT = [
    [:kem_output, :vec]
  ]
end

class MLSStruct::GroupContextExtensions < MLSStruct::Base
  attr_reader :extensions
  STRUCT = [
    [:extensions, :classes, MLSStruct::Extension]
  ]
end

## 12.1.8.1

class MLSStruct::ExternalSender < MLSStruct::Base
  attr_reader :signature_key, :credential
  STRUCT = [
    [:signature_key, :vec],
    [:credential, :class, MLSStruct::Credential]
  ]
end

## 12.1

class MLSStruct::Proposal < MLSStruct::Base
  attr_reader :proposal_type, :add, :update, :remove, :psk, :reinit, :external_init, :group_context_extensions
  STRUCT = [
    [:proposal_type, :uint16],
    [:add, :select, ->(ctx){ctx[:proposal_type] == 0x01}, :class, MLSStruct::Add],
    [:update, :select, ->(ctx){ctx[:proposal_type] == 0x02}, :class, MLSStruct::Update],
    [:remove, :select, ->(ctx){ctx[:proposal_type] == 0x03}, :class, MLSStruct::Remove],
    [:psk, :select, ->(ctx){ctx[:proposal_type] == 0x04}, :class, MLSStruct::PreSharedKey],
    [:reinit, :select, ->(ctx){ctx[:proposal_type] == 0x05}, :class, MLSStruct::ReInit],
    [:external_init, :select, ->(ctx){ctx[:proposal_type] == 0x06}, :class, MLSStruct::ExternalInit],
    [:group_context_extensions, :select, ->(ctx){ctx[:proposal_type] == 0x07}, :class, MLSStruct::GroupContextExtensions],
  ]

  def proposal_content
    @add || @update || @remove || @psk || @reinit || @external_init || @group_context_extensions
  end
end

## 12.4

class MLSStruct::ProposalOrRef < MLSStruct::Base
  attr_reader :type, :proposal, :reference
  STRUCT = [
    [:type, :uint8],
    [:proposal, :select,  ->(ctx){ctx[:type] == 0x01}, :class, MLSStruct::Proposal],
    [:reference, :select, ->(ctx){ctx[:type] == 0x02}, :vec] # ProposalRef is a HashReference, which is a :vec
  ]
end

class MLSStruct::Commit < MLSStruct::Base
  attr_reader :proposals, :path
  STRUCT = [
    [:proposals, :classes, MLSStruct::ProposalOrRef],
    [:path, :optional, MLSStruct::UpdatePath]
  ]
end

## 12.4.3

class MLSStruct::GroupInfo < MLSStruct::Base
  attr_reader :group_context, :extensions, :confirmation_tag, :signer, :signature
  STRUCT = [
    [:group_context, :class, MLSStruct::GroupContext],
    [:extensions, :classes, MLSStruct::Extension],
    [:confirmation_tag, :vec], # MAC = opaque <V>
    [:signer, :uint32],
    [:signature, :vec]
  ]

  def group_info_tbs
    MLSStruct::GroupInfoTBS.create(
      group_context:,
      extensions:,
      confirmation_tag:,
      signer:
    )
  end

  def sign(signer_private)
    MLS::Crypto.sign_with_label(signer_private_key, "GroupInfoTBS", group_info_tbs.raw)
  end

  def verify(signer_public_key)
    MLS::Crypto.verify_with_label(signer_public_key, "GroupInfoTBS", group_info_tbs.raw, signature)
  end
end


class MLSStruct::GroupInfoTBS < MLSStruct::Base
  attr_reader :group_context, :extensions, :confirmation_tag, :signer, :signature
  STRUCT = [
    [:group_context, :class, MLSStruct::GroupContext],
    [:extensions, :classes, MLSStruct::Extension],
    [:confirmation_tag, :vec], # MAC = opaque <V>
    [:signer, :uint32]
  ]

  def self.create(group_context:, extensions:, confirmation_tag:, signer:)
    new_instance = self.allocate
    new_instance.instance_variable_set(:@group_context, group_context)
    new_instance.instance_variable_set(:@extensions, extensions)
    new_instance.instance_variable_set(:@confirmation_tag, confirmation_tag)
    new_instance.instance_variable_set(:@signer, signer)
    new_instance
  end
end

# 12.4.3.1

class MLSStruct::PathSecret < MLSStruct::Base
  attr_reader :path_secret
  STRUCT = [
    [:path_secret, :vec]
  ]
end

class MLSStruct::GroupSecrets < MLSStruct::Base
  attr_reader :joiner_secret, :path_secret, :psks
  STRUCT = [
    [:joiner_secret, :vec],
    [:path_secret, :optional, MLSStruct::PathSecret],
    [:psks, :classes, MLSStruct::PreSharedKeyID]
  ]
end

class MLSStruct::EncryptedGroupSecrets < MLSStruct::Base
  attr_reader :new_member, :encrypted_group_secrets
  STRUCT = [
    [:new_member, :vec], # KeyPackageRef = opaque <V>
    [:encrypted_group_secrets, :class, MLSStruct::HPKECipherText]
  ]
end

class MLSStruct::Welcome < MLSStruct::Base
  attr_reader :cipher_suite, :secrets, :encrypted_group_info
  STRUCT = [
    [:cipher_suite, :uint16],
    [:secrets, :classes, MLSStruct::EncryptedGroupSecrets],
    [:encrypted_group_info, :vec]
  ]
end

## 12.4.3.2

class MLSStruct::ExternalPub < MLSStruct::Base
  attr_reader :external_pub
  STRUCT = [
    [:external_pub, :vec] # HPKEPublicKey
  ]
end

class MLSStruct::Node < MLSStruct::Base
  attr_reader :node_type, :leaf_node, :parent_node
  STRUCT = [
    [:node_type, :uint8],
    [:leaf_node,   :select, ->(ctx){ctx[:node_type] == 0x01}, :class, MLSStruct::LeafNode], # leaf
    [:parent_node, :select, ->(ctx){ctx[:node_type] == 0x02}, :class, MLSStruct::ParentNode] # parent
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

class MLSStruct::FramedContentAuthData < MLSStruct::Base
  attr_reader :signature, :confirmation_tag, :content_type

  STRUCT = [
    [:signature, :vec]
  ]

  # initialize from stream
  def self.new_and_rest_with_content_type(buf, content_type)
    instance = self.allocate
    context, buf = instance.send(:deserialize, buf)
    # custom part based on instance variable
    if content_type == 0x03 # commit
      # read MAC(opaque <V>) confirmation_tag
      value, buf = String.parse_vec(buf)
      context << [:confirmation_tag, value]
    end
    context << [:content_type, content_type]
    instance.send(:set_instance_vars, context)
    [instance, buf]
  end

  def raw
    if @content_type == 0x03
      @signature.to_vec + @confirmation_tag.to_vec
    else
      @signature.to_vec
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
    [:application_data, :select, ->(context){context[:content_type] == 0x01}, :vec],
    [:proposal,         :select, ->(context){context[:content_type] == 0x02}, :class, MLSStruct::Proposal],
    [:commit,           :select, ->(context){context[:content_type] == 0x03}, :class, MLSStruct::Commit]
  ]

  def content_tbs(version, wire_format, group_context)
    buf = [version].pack('S>') + [wire_format].pack('S>') + self.raw
    case sender.sender_type
    when 0x01, 0x04 # member, new_member_commit
      buf += group_context.raw
    when 0x02, 0x03 # external, new_member_proposal
      # do nothing
    end
  end
end

class MLSStruct::FramedContentTBS < MLSStruct::Base
  attr_reader :version, :wire_format, :content, :context
  STRUCT = [
    [:version, :uint16], #mls10 = 1
    [:wire_format, :uint16],
    [:content, :class, MLSStruct::FramedContent],
    [:context, :select, ->(ctx){[0x01, 0x04].include?(ctx[:content].sender.sender_type)}, :class, MLSStruct::GroupContext]
  ]
end

class MLSStruct::AuthenticatedContent < MLSStruct::Base
  attr_reader :wire_format, :content, :auth
  STRUCT = [
    [:wire_format, :uint16],
    [:content, :class, MLSStruct::FramedContent],
    [:auth, :framed_content_auth_data]
  ]

  def content_tbm
    content.content_tbs(0x01, wire_format) + auth.raw
  end

  def confirmed_transcript_hash_input
    MLSStruct::ConfirmedTranscriptHashInput.create(
      wire_format: wire_format,
      content: content,
      signature: auth.signature
    )
  end
end

## 6.2

class MLSStruct::PublicMessage < MLSStruct::Base
  attr_reader :content, :auth, :membership_tag
  STRUCT = [
    [:content, :class, MLSStruct::FramedContent],
    [:auth, :framed_content_auth_data],
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

## 8.2

class MLSStruct::ConfirmedTranscriptHashInput < MLSStruct::Base
  attr_accessor :wire_format, :content, :signature
  STRUCT = [
    [:wire_format, :uint16],
    [:content, :class, MLSStruct::FramedContent], # with content_type == commit
    [:signature, :vec]
  ]

  def self.create(wire_format:, content:, signature:)
    new_instance = self.allocate
    new_instance.instance_variable_set(:@wire_format, wire_format)
    new_instance.instance_variable_set(:@content, content)
    new_instance.instance_variable_set(:@signature, signature)
    new_instance
  end
end

class MLSStruct::InterimTranscriptHashInput < MLSStruct::Base
  attr_reader :confirmation_tag
  STRUCT = [
    [:confirmation_tag, :vec]
  ]
end

class MLSStruct::MLSMessage < MLSStruct::Base
  attr_accessor :version, :wire_format, :public_message, :private_message, :welcome, :group_info, :key_package
  STRUCT = [
    [:version, :uint16], #mls10 = 1
    [:wire_format, :uint16],
    [:public_message,  :select, ->(ctx){ctx[:wire_format] == 0x0001}, :class, MLSStruct::PublicMessage],
    [:private_message, :select, ->(ctx){ctx[:wire_format] == 0x0002}, :class, MLSStruct::PrivateMessage],
    [:welcome,         :select, ->(ctx){ctx[:wire_format] == 0x0003}, :class, MLSStruct::Welcome],
    [:group_info,      :select, ->(ctx){ctx[:wire_format] == 0x0004}, :class, MLSStruct::GroupInfo],
    [:key_package,     :select, ->(ctx){ctx[:wire_format] == 0x0005}, :class, MLSStruct::KeyPackage]
  ]
end

## Ratchet Tree Extension (12.4.3.3)
module MLSStruct::RatchetTree
  def self.parse(vec)
    array, _ = new_and_rest(vec)
    array
  end

  def self.new_and_rest(vec)
    array = []
    buf, rest = String.parse_vec(vec)
    while buf.bytesize > 0
      presence = buf.byteslice(0, 1).unpack1('C')
      buf = buf.byteslice(1..)
      case presence
      when 0
        array << nil
      when 1
        node, buf = MLSStruct::Node.new_and_rest(buf)
        array << node
      end
    end
    [array, rest]
  end

  def self.raw(array)
    buf = ''
    array.each do |optional_node|
      if optional_node.nil?
        buf += [0].pack('C')
      else
        buf += [1].pack('C')
        buf += optional_node.raw
      end
    end

    buf.to_vec
  end
end
