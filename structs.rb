require_relative 'vec_base.rb'
require_relative 'mls_struct_base.rb'
require 'securerandom'

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

  def self.create(leaf_index:, generation:, reuse_guard:)
    new_instance = self.allocate
    new_instance.instance_variable_set(:@leaf_index, leaf_index)
    new_instance.instance_variable_set(:@generation, generation)
    new_instance.instance_variable_set(:@reuse_guard, reuse_guard)
    new_instance
  end
end

## 7.1

class MLSStruct::ParentNode < MLSStruct::Base
  attr_reader :encryption_key, :parent_hash, :unmerged_leaves
  STRUCT = [
    [:encryption_key, :vec], # HPKEPublicKey = opaque <V>
    [:parent_hash, :vec],
    [:unmerged_leaves, :vec_of_type, :uint32] # becomes a vec of uint32
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

  def leaf_node_tbs(group_id, leaf_index)
    buf = ''
    buf += encryption_key.to_vec
    buf += signature_key.to_vec
    buf += credential.raw
    buf += capabilities.raw
    buf += [leaf_node_source].pack('C')
    if leaf_node_source == 0x01
      buf += lifetime.raw
    elsif leaf_node_source == 0x03
      buf += parent_hash.to_vec
    end
    buf += extensions.map(&:raw).join.to_vec
    if leaf_node_source == 0x02 || leaf_node_source == 0x03
      buf += group_id.to_vec
      buf += [leaf_index].pack('L>') # uint32
    end
    buf
  end

  def verify(suite, group_id, leaf_index)
    MLS::Crypto.verify_with_label(suite, signature_key, "LeafNodeTBS", leaf_node_tbs(group_id, leaf_index), signature)
  end
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

  def ref(suite)
    MLS::Crypto.make_keypackage_ref(suite, self.raw)
  end
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

  def sign(suite, signer_private)
    MLS::Crypto.sign_with_label(suite, signer_private_key, "GroupInfoTBS", group_info_tbs.raw)
  end

  def verify(suite, signer_public_key)
    MLS::Crypto.verify_with_label(suite, signer_public_key, "GroupInfoTBS", group_info_tbs.raw, signature)
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

  def parent_hash_in_node
    @leaf_node&.parent_hash || @parent_node.parent_hash
  end
end

# Section 6.1
class MLSStruct::Sender < MLSStruct::Base
  attr_reader :sender_type, :leaf_index, :sender_index
  STRUCT = [
    [:sender_type, :uint8],
    [:leaf_index,   :select, ->(ctx){ctx[:sender_type] == 0x01}, :uint32], # 0x01 = member
    [:sender_index, :select, ->(ctx){ctx[:sender_type] == 0x02}, :uint32], # 0x02 = external
  ]

  def self.create_member(leaf_index)
    instance = self.allocate
    instance.instance_variable_set(:@sender_type, 0x01)
    instance.instance_variable_set(:@leaf_index, leaf_index)
    instance
  end

  def self.create_external(sender_index)
    instance = self.allocate
    instance.instance_variable_set(:@sender_type, 0x02)
    instance.instance_variable_set(:@sender_index, sender_index)
    instance
  end
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

  def self.create(signature:, content_type:, confirmation_tag:)
    instance = self.allocate
    instance.instance_variable_set(:@signature, signature)
    instance.instance_variable_set(:@content_type, content_type)
    if content_type == 0x03
      instance.instance_variable_set(:@confirmation_tag, confirmation_tag)
    end
    instance
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
    buf
  end

  def self.create(group_id:, epoch:, sender:, authenticated_data:, content_type:, content:)
    new_instance = self.allocate
    new_instance.instance_variable_set(:@group_id, group_id)
    new_instance.instance_variable_set(:@epoch, epoch)
    new_instance.instance_variable_set(:@sender, sender)
    new_instance.instance_variable_set(:@authenticated_data, authenticated_data)
    new_instance.instance_variable_set(:@content_type, content_type)
    case content_type
    when 0x01 # application_data
      new_instance.instance_variable_set(:@application_data, content)
    when 0x02 # proposal
      new_instance.instance_variable_set(:@proposal, content)
    when 0x03 # commit
      new_instance.instance_variable_set(:@commit, content)
    end
    new_instance
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

  def verify(suite, signature_public_key, context)
    return false if (wire_format == 0x01 && content.content_type == 0x01)

    content_tbs = content.content_tbs(0x01, wire_format, context)

    return MLS::Crypto.verify_with_label(suite, signature_public_key, "FramedContentTBS", content_tbs, auth.signature)
  end

  def self.create(wire_format:, content:, auth:)
    new_instance = self.allocate
    new_instance.instance_variable_set(:@wire_format, wire_format)
    new_instance.instance_variable_set(:@content, content)
    new_instance.instance_variable_set(:@auth, auth)
    new_instance
  end

  # populate auth with values
  def sign(suite, signature_private_key, group_context)
    raise ArgumentError.new('Application data cannot be sent as a PublicMessage') if wire_format == 0x01 && content.content_type == 0x01
    content_tbs = content.content_tbs(0x01, wire_format, group_context)
    signature = MLS::Crypto.sign_with_label(suite, signature_private_key, "FramedContentTBS", content_tbs)
    @auth = MLSStruct::FramedContentAuthData.create(
      signature: signature,
      content_type: content.content_type,
      confirmation_tag: nil
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

  def self.protect(authenticated_content, suite, membership_key, group_context)
    message = self.allocate
    message.instance_variable_set(:@content, authenticated_content.content)
    message.instance_variable_set(:@auth, authenticated_content.auth)
    if message.content.sender.sender_type == 0x01 # member
      message.instance_variable_set(:@membership_tag, message.membership_mac(suite, membership_key, group_context))
    end
    message
  end

  def unprotect(suite, membership_key, group_context)
    ## if sender type is member then membershipMac(suite, membership_key, group_context)
    if (content.sender.sender_type == 0x01)
      return nil if membership_tag != membership_mac(suite, membership_key, group_context)
    end
    MLSStruct::AuthenticatedContent.create(
      wire_format: 0x01, # public_message
      content: content,
      auth: auth
    )
  end

  def membership_mac(suite, membership_key, group_context)
    authenticated_content_tbm = content.content_tbs(0x01, 0x01, group_context) + auth.raw
    MLS::Crypto.mac(suite, membership_key, authenticated_content_tbm)
  end
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

  def self.create(group_id:, epoch:, content_type:, authenticated_data:, encrypted_sender_data:, ciphertext:)
    new_instance = self.allocate
    new_instance.instance_variable_set(:@group_id, group_id)
    new_instance.instance_variable_set(:@epoch, epoch)
    new_instance.instance_variable_set(:@content_type, content_type)
    new_instance.instance_variable_set(:@authenticated_data, authenticated_data)
    new_instance.instance_variable_set(:@encrypted_sender_data, encrypted_sender_data)
    new_instance.instance_variable_set(:@ciphertext, ciphertext)
    new_instance
  end

  def sender_data_aad
    self.class.sender_data_aad_impl(group_id, epoch, content_type)
  end

  def self.sender_data_aad_impl(gid, ep, ct)
    gid.to_vec + [ep].pack('Q>') + [ct].pack('C')
  end

  def private_content_aad
    self.class.private_content_aad_impl(group_id, epoch, content_type, authenticated_data)
  end

  def self.private_content_aad_impl(gid, ep, ct, ad)
    gid.to_vec + [ep].pack('Q>') + [ct].pack('C') + ad.to_vec
  end

  def self.protect(authenticated_content, suite, secret_tree, sender_data_secret, padding_size)
    leaf_index = authenticated_content.content.sender.leaf_index
    content_type = authenticated_content.content.content_type
    reuse_guard = SecureRandom.random_bytes(4)
    key, nonce, generation = MLS::SecretTree::ratchet_and_get(suite, content_type, secret_tree, leaf_index)
    new_nonce = apply_nonce_reuse_guard(nonce, reuse_guard)

    private_message_content_plain = serialize_private_message_content(authenticated_content.content, authenticated_content.auth, padding_size)
    aad = private_content_aad_impl(
      authenticated_content.content.group_id,
      authenticated_content.content.epoch,
      authenticated_content.content.content_type,
      authenticated_content.content.authenticated_data)
    private_message_content_ciphertext = MLS::Crypto.aead_encrypt(suite, key, new_nonce, aad, private_message_content_plain)

    sender_data_plain = MLSStruct::SenderData.create(
      leaf_index: leaf_index,
      generation: generation,
      reuse_guard: reuse_guard
    )
    sd_aad = sender_data_aad_impl(
      authenticated_content.content.group_id,
      authenticated_content.content.epoch,
      authenticated_content.content.content_type)
    sender_data_key   = MLS::Crypto.sender_data_key(suite, sender_data_secret, private_message_content_ciphertext)
    sender_data_nonce = MLS::Crypto.sender_data_nonce(suite, sender_data_secret, private_message_content_ciphertext)
    sender_data_ciphertext = MLS::Crypto.aead_encrypt(suite, sender_data_key, sender_data_nonce, sd_aad, sender_data_plain.raw)

    create(
      group_id: authenticated_content.content.group_id,
      epoch: authenticated_content.content.epoch,
      content_type: authenticated_content.content.content_type,
      authenticated_data: authenticated_content.content.authenticated_data,
      encrypted_sender_data: sender_data_ciphertext,
      ciphertext: private_message_content_ciphertext
    )
  end

  def unprotect(suite, secret_tree, sender_data_secret)
    sender_data = decrypt_sender_data(suite, sender_data_secret)
    key, nonce, _ = MLS::SecretTree.ratchet_until_and_get(suite, content_type, secret_tree, sender_data.leaf_index, sender_data.generation)
    new_nonce = self.class.apply_nonce_reuse_guard(nonce, sender_data.reuse_guard)
    pmc, _ = MLSStruct::PrivateMessageContent.new_and_rest_with_content_type(MLS::Crypto.aead_decrypt(suite, key, new_nonce, private_content_aad, ciphertext), content_type)

    fc = MLSStruct::FramedContent.create(
      group_id: group_id,
      epoch: epoch,
      sender: MLSStruct::Sender.create_member(sender_data.leaf_index),
      authenticated_data: authenticated_data,
      content_type: content_type,
      content: pmc.content
    )

    MLSStruct::AuthenticatedContent.create(
      wire_format: 0x0002, # private_message
      content: fc,
      auth: pmc.auth
    )
  end

  private
  def decrypt_sender_data(suite, sender_data_secret)
    sender_data_key   = MLS::Crypto.sender_data_key(suite, sender_data_secret, ciphertext)
    sender_data_nonce = MLS::Crypto.sender_data_nonce(suite, sender_data_secret, ciphertext)
    MLSStruct::SenderData.new(MLS::Crypto.aead_decrypt(suite, sender_data_key, sender_data_nonce, sender_data_aad, encrypted_sender_data))
  end

  def self.apply_nonce_reuse_guard(nonce, guard)
    guard_arr = guard.unpack('c*')
    nonce_arr = nonce.unpack('c*')
    guard_arr.each_with_index do |char, index|
      nonce_arr[index] = nonce_arr[index] ^ char
    end
    nonce_arr.pack('C*')
  end

  def self.serialize_private_message_content(framed_content, framed_content_auth_data, padding_size)
    buf = ''
    case framed_content.content_type
    when 0x01 # application
      buf += framed_content.application_data.to_vec
    when 0x02 # proposal
      buf += framed_content.proposal.raw
    when 0x03 # commit
      buf += framed_content.commit.raw
    end
    buf += framed_content_auth_data.signature.to_vec
    if framed_content.content_type == 0x03 # commit
      buf += framed_content_auth_data.confirmation_tag.to_vec
    end
    buf += MLS::Crypto::Util.zero_vector(padding_size)
    buf
  end
end

class MLSStruct::PrivateMessageContent < MLSStruct::Base
  attr_accessor :application_data, :proposal, :commit, :auth, :padding
  # bytes -> struct: decode the content and auth field, rest is padding
  # struct -> bytes: encode content and auth field, add set amount of padding (zero bytes)

  def self.new_and_rest_with_content_type(buf, content_type)
    instance = self.allocate
    context = []
    # deserialize application_data/proposal/commit
    case content_type
    when 0x01 # application
      value, buf = String.parse_vec(buf)
      context << [:application_data, value]
    when 0x02 # proposal
      value, buf = MLSStruct::Proposal.new_and_rest(buf)
      context << [:proposal, value]
    when 0x03 # commit
      value, buf = MLSStruct::Commit.new_and_rest(buf)
      context << [:commit, value]
    end
    fcad, buf = MLSStruct::FramedContentAuthData.new_and_rest_with_content_type(buf, content_type)
    context << [:auth, fcad]
    # assume rest is padding
    context << [:padding, buf]
    instance.send(:set_instance_vars, context)
    [instance, '']
  end

  def content
    @application_data || @proposal || @commit
  end
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

  def verify(suite, signer_public_key, group_context)
    if wire_format == 0x0001
      public_message.verify(suite, signer_public_key, version, wire_format, group_context)
    end
  end
end
