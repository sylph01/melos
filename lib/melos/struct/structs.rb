require_relative '../vec'
require_relative 'base'
require 'securerandom'

class Melos::Struct::EncryptContext < Melos::Struct::Base
  attr_reader :label, :context
  STRUCT = [
    [:label, :vec],
    [:context, :vec]
  ]
end

class Melos::Struct::RefHashInput < Melos::Struct::Base
  attr_reader :label, :value
  STRUCT = [
    [:label, :vec],
    [:value, :vec]
  ]
end

# Section 5.3 Credentials
class Melos::Struct::Certificate < Melos::Struct::Base
  attr_reader :cert_data
  STRUCT = [
    [:cert_data, :vec]
  ]
end

class Melos::Struct::Credential < Melos::Struct::Base
  attr_reader :credential_type, :identity, :certificates
  STRUCT = [
    [:credential_type, :uint16],
    [:identity,     :select, ->(ctx){ctx[:credential_type] == Melos::Constants::CredentialType::BASIC}, :vec],
    [:certificates, :select, ->(ctx){ctx[:credential_type] == Melos::Constants::CredentialType::X509},  :classes, Melos::Struct::Certificate]
  ]
end

## 6.3.2

class Melos::Struct::SenderData < Melos::Struct::Base
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

class Melos::Struct::ParentNode < Melos::Struct::Base
  attr_reader :encryption_key, :parent_hash, :unmerged_leaves
  STRUCT = [
    [:encryption_key, :vec], # HPKEPublicKey = opaque <V>
    [:parent_hash, :vec],
    [:unmerged_leaves, :vec_of_type, :uint32] # becomes a vec of uint32
  ]

  def self.create(encryption_key:, parent_hash:, unmerged_leaves:)
    new_instance = self.allocate
    new_instance.instance_variable_set(:@encryption_key, encryption_key)
    new_instance.instance_variable_set(:@parent_hash, parent_hash)
    new_instance.instance_variable_set(:@unmerged_leaves, unmerged_leaves)
    new_instance
  end
end

## 7.2

class Melos::Struct::Capabilities < Melos::Struct::Base
  attr_reader :versions, :cipher_suites, :extensions, :proposals, :credentials
  STRUCT = [
    [:versions, :vec],      # vec of ProtocolVersion (uint16)
    [:cipher_suites, :vec], # vec of CipherSuite (uint16)
    [:extensions, :vec],    # vec of ExtensionType (uint16)
    [:proposals, :vec],     # vec of ProposalTypes (uint16)
    [:credentials, :vec]    # vec of CredentialTypes (uint16)
  ]
end

class Melos::Struct::Lifetime < Melos::Struct::Base
  attr_reader :not_before, :not_after
  STRUCT = [
    [:not_before, :uint64],
    [:not_after, :uint64]
  ]
end

class Melos::Struct::Extension < Melos::Struct::Base
  attr_reader :extension_type, :extension_data
  STRUCT = [
    [:extension_type, :uint16], # ExtensionType = uint16
    [:extension_data, :vec]
  ]
end

class Melos::Struct::LeafNode < Melos::Struct::Base
  attr_reader :encryption_key, :signature_key, :credential, :capabilities, :leaf_node_source, :lifetime, :parent_hash, :extensions, :signature
  STRUCT = [
    [:encryption_key, :vec], # HPKEPublicKey = opaque <V>
    [:signature_key, :vec],  # SignaturePublicKey = opaque <V>
    [:credential, :class, Melos::Struct::Credential],
    [:capabilities, :class, Melos::Struct::Capabilities],
    [:leaf_node_source, :uint8], # LeafNodeSource = enum of uint8,
    [:lifetime, :select,    ->(ctx){ctx[:leaf_node_source] == Melos::Constants::LeafNodeSource::KEY_PACKAGE}, :class, Melos::Struct::Lifetime],
    [:parent_hash, :select, ->(ctx){ctx[:leaf_node_source] == Melos::Constants::LeafNodeSource::COMMIT},      :vec],
    [:extensions, :classes, Melos::Struct::Extension],
    [:signature, :vec]
  ]

  def leaf_node_tbs(group_id, leaf_index)
    buf = ''
    buf += Melos::Vec.from_string(encryption_key)
    buf += Melos::Vec.from_string(signature_key)
    buf += credential.raw
    buf += capabilities.raw
    buf += [leaf_node_source].pack('C')
    if leaf_node_source == Melos::Constants::LeafNodeSource::KEY_PACKAGE
      buf += lifetime.raw
    elsif leaf_node_source == Melos::Constants::LeafNodeSource::COMMIT
      buf += Melos::Vec.from_string(parent_hash)
    end
    buf += Melos::Vec.from_string(extensions.map(&:raw).join)
    if leaf_node_source == Melos::Constants::LeafNodeSource::UPDATE || leaf_node_source == Melos::Constants::LeafNodeSource::COMMIT
      buf += Melos::Vec.from_string(group_id)
      buf += [leaf_index].pack('L>') # uint32
    end
    buf
  end

  def self.create(
    encryption_key:, signature_key:, credential:, capabilities:,
    leaf_node_source:, lifetime:, parent_hash:, extensions:, signature:
  )
    new_instance = self.allocate
    new_instance.instance_variable_set(:@encryption_key, encryption_key)
    new_instance.instance_variable_set(:@signature_key, signature_key)
    new_instance.instance_variable_set(:@credential, credential)
    new_instance.instance_variable_set(:@capabilities, capabilities)
    new_instance.instance_variable_set(:@leaf_node_source, leaf_node_source)
    new_instance.instance_variable_set(:@lifetime, lifetime)
    new_instance.instance_variable_set(:@parent_hash, parent_hash)
    new_instance.instance_variable_set(:@extensions, extensions)
    new_instance.instance_variable_set(:@signature, signature)
    new_instance
  end

  def sign(suite, signature_private_key, group_id, leaf_index)
    @signature = Melos::Crypto.sign_with_label(suite, signature_private_key, "LeafNodeTBS", leaf_node_tbs(group_id, leaf_index))
  end

  def verify(suite, group_id, leaf_index)
    Melos::Crypto.verify_with_label(suite, signature_key, "LeafNodeTBS", leaf_node_tbs(group_id, leaf_index), signature)
  end
end

## 7.6

class Melos::Struct::HPKECipherText < Melos::Struct::Base
  attr_reader :kem_output, :ciphertext
  STRUCT = [
    [:kem_output, :vec],
    [:ciphertext, :vec]
  ]

  def self.create(kem_output:, ciphertext:)
    new_instance = self.allocate
    new_instance.instance_variable_set(:@kem_output, kem_output)
    new_instance.instance_variable_set(:@ciphertext, ciphertext)
    new_instance
  end
end

class Melos::Struct::UpdatePathNode < Melos::Struct::Base
  attr_reader :encryption_key, :encrypted_path_secret
  STRUCT = [
    [:encryption_key, :vec], # HPKEPublicKey = opaque <V>
    [:encrypted_path_secret, :classes, Melos::Struct::HPKECipherText]
  ]

  def self.create(encryption_key:, encrypted_path_secret:)
    new_instance = self.allocate
    new_instance.instance_variable_set(:@encryption_key, encryption_key)
    new_instance.instance_variable_set(:@encrypted_path_secret, encrypted_path_secret)
    new_instance
  end
end

class Melos::Struct::UpdatePath < Melos::Struct::Base
  attr_reader :leaf_node, :nodes
  STRUCT = [
    [:leaf_node, :class, Melos::Struct::LeafNode],
    [:nodes, :classes, Melos::Struct::UpdatePathNode]
  ]

  def self.create(leaf_node:, nodes:)
    new_instance = self.allocate
    new_instance.instance_variable_set(:@leaf_node, leaf_node)
    new_instance.instance_variable_set(:@nodes, nodes)
    new_instance
  end
end

## 7.8

## NodeType: uint8 enum

class Melos::Struct::LeafNodeHashInput < Melos::Struct::Base
  attr_reader :leaf_index, :leaf_node
  STRUCT = [
    [:leaf_index, :uint32],
    [:leaf_node, :optional, Melos::Struct::LeafNode]
  ]
end

class Melos::Struct::ParentNodeHashInput < Melos::Struct::Base
  attr_reader :parent_node, :left_hash, :right_hash
  STRUCT = [
    [:parent_node, :optional, Melos::Struct::ParentNode],
    [:left_hash, :vec],
    [:right_hash, :vec]
  ]
end

## 7.9

class Melos::Struct::ParentHashInput < Melos::Struct::Base
  attr_reader :encryption_key, :parent_hash, :original_sibling_tree_hash
  STRUCT = [
    [:encryption_key, :vec], # HPKEPublicKey
    [:parent_hash, :vec],
    [:original_sibling_tree_hash, :vec]
  ]
end

class Melos::Struct::TreeHashInput < Melos::Struct::Base
  attr_reader :node_type, :leaf_node, :parent_node
  STRUCT = [
    [:node_type, :uint8],
    [:leaf_node,   :select, ->(ctx){ctx[:node_type] == Melos::Constants::NodeType::LEAF},   :class, Melos::Struct::LeafNodeHashInput],
    [:parent_node, :select, ->(ctx){ctx[:node_type] == Melos::Constants::NodeType::PARENT}, :class, Melos::Struct::ParentNodeHashInput],
  ]
end

## 8

class Melos::Struct::KDFLabel < Melos::Struct::Base
  attr_reader :length, :label, :context
  STRUCT = [
    [:length, :uint16],
    [:label, :vec],
    [:context, :vec]
  ]
end

## 8.1

class Melos::Struct::GroupContext < Melos::Struct::Base
  attr_reader :version, :cipher_suite, :group_id, :epoch, :tree_hash, :confirmed_transcript_hash, :extensions
  STRUCT = [
    [:version, :uint16],
    [:cipher_suite, :uint16],
    [:group_id, :vec],
    [:epoch, :uint64],
    [:tree_hash, :vec],
    [:confirmed_transcript_hash, :vec],
    [:extensions, :classes, Melos::Struct::Extension]
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

class Melos::Struct::PreSharedKeyID < Melos::Struct::Base
  attr_reader :psktype, :psk_id, :psk_group_id, :psk_epoch, :psk_nonce
  STRUCT = [
    [:psktype, :uint8],
    [:psk_id,       :select, ->(ctx){ctx[:psktype] == Melos::Constants::PSKType::EXTERNAL}, :vec],    # external
    [:psk_group_id, :select, ->(ctx){ctx[:psktype] == Melos::Constants::PSKType::RESUMPTION}, :vec],    # resumption
    [:psk_epoch,    :select, ->(ctx){ctx[:psktype] == Melos::Constants::PSKType::RESUMPTION}, :uint64], # resumption
    [:psk_nonce, :vec]
  ]

  def self.create_external(psk_id:, psk_nonce:)
    new_instance = self.allocate
    new_instance.instance_variable_set(:@psktype, Melos::Constants::PSKType::EXTERNAL)
    new_instance.instance_variable_set(:@psk_id, psk_id)
    new_instance.instance_variable_set(:@psk_nonce, psk_nonce)
    new_instance
  end
end

class Melos::Struct::PSKLabel < Melos::Struct::Base
  attr_reader :id, :index, :count
  STRUCT = [
    [:id, :class, Melos::Struct::PreSharedKeyID],
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

class Melos::Struct::KeyPackage < Melos::Struct::Base
  attr_reader :version, :cipher_suite, :init_key, :leaf_node, :extensions, :signature
  STRUCT = [
    [:version, :uint16],
    [:cipher_suite, :uint16],
    [:init_key, :vec], # HPKEPublicKey
    [:leaf_node, :class, Melos::Struct::LeafNode],
    [:extensions, :classes, Melos::Struct::Extension],
    [:signature, :vec] # SignWithLabel(., "KeyPackageTBS", KeyPackageTBS)
  ]

  def ref(suite)
    Melos::Crypto.make_keypackage_ref(suite, self.raw)
  end
end

class Melos::Struct::KeyPackageTBS < Melos::Struct::Base
  attr_reader :version, :cipher_suite, :init_key, :leaf_node, :extensions
  STRUCT = [
    [:version, :uint16],
    [:cipher_suite, :uint16],
    [:init_key, :vec], # HPKEPublicKey
    [:leaf_node, :class, Melos::Struct::LeafNode],
    [:extensions, :classes, Melos::Struct::Extension]
  ]
end

## 11

class Melos::Struct::RequiredCapabilities < Melos::Struct::Base
  attr_reader :extension_types, :proposal_types, :credential_types
  STRUCT = [
    [:extension_types, :vec], # vec of uint16
    [:proposal_types, :vec], # vec of uint16
    [:credential_types, :vec] # vec of uint16
  ]
end

## 12

## 12.1.1 - 12.1.7

class Melos::Struct::Add < Melos::Struct::Base
  attr_reader :key_package
  STRUCT = [
    [:key_package, :class, Melos::Struct::KeyPackage]
  ]
end

class Melos::Struct::Update < Melos::Struct::Base
  attr_reader :leaf_node
  STRUCT = [
    [:leaf_node, :class, Melos::Struct::LeafNode]
  ]
end

class Melos::Struct::Remove < Melos::Struct::Base
  attr_reader :removed
  STRUCT = [
    [:removed, :uint32]
  ]
end

class Melos::Struct::PreSharedKey < Melos::Struct::Base
  attr_reader :psk
  STRUCT = [
    [:psk, :class, Melos::Struct::PreSharedKeyID]
  ]
end

class Melos::Struct::ReInit < Melos::Struct::Base
  attr_reader :group_id, :version, :cipher_suite, :extensions
  STRUCT = [
    [:group_id, :vec],
    [:version, :uint16],
    [:cipher_suite, :uint16],
    [:extensions, :classes, Melos::Struct::Extension]
  ]
end

class Melos::Struct::ExternalInit < Melos::Struct::Base
  attr_reader :kem_output
  STRUCT = [
    [:kem_output, :vec]
  ]
end

class Melos::Struct::GroupContextExtensions < Melos::Struct::Base
  attr_reader :extensions
  STRUCT = [
    [:extensions, :classes, Melos::Struct::Extension]
  ]
end

## 12.1.8.1

class Melos::Struct::ExternalSender < Melos::Struct::Base
  attr_reader :signature_key, :credential
  STRUCT = [
    [:signature_key, :vec],
    [:credential, :class, Melos::Struct::Credential]
  ]
end

## 12.1

class Melos::Struct::Proposal < Melos::Struct::Base
  attr_reader :proposal_type, :add, :update, :remove, :psk, :reinit, :external_init, :group_context_extensions
  STRUCT = [
    [:proposal_type, :uint16],
    [:add, :select, ->(ctx){ctx[:proposal_type] == Melos::Constants::ProposalType::ADD}, :class, Melos::Struct::Add],
    [:update, :select, ->(ctx){ctx[:proposal_type] == Melos::Constants::ProposalType::UPDATE}, :class, Melos::Struct::Update],
    [:remove, :select, ->(ctx){ctx[:proposal_type] == Melos::Constants::ProposalType::REMOVE}, :class, Melos::Struct::Remove],
    [:psk, :select, ->(ctx){ctx[:proposal_type] == Melos::Constants::ProposalType::PSK}, :class, Melos::Struct::PreSharedKey],
    [:reinit, :select, ->(ctx){ctx[:proposal_type] == Melos::Constants::ProposalType::REINIT}, :class, Melos::Struct::ReInit],
    [:external_init, :select, ->(ctx){ctx[:proposal_type] == Melos::Constants::ProposalType::EXTERNAL_INIT}, :class, Melos::Struct::ExternalInit],
    [:group_context_extensions, :select, ->(ctx){ctx[:proposal_type] == Melos::Constants::ProposalType::GROUP_CONTEXT_EXTENSIONS}, :class, Melos::Struct::GroupContextExtensions],
  ]

  def proposal_content
    @add || @update || @remove || @psk || @reinit || @external_init || @group_context_extensions
  end
end

## 12.4

class Melos::Struct::ProposalOrRef < Melos::Struct::Base
  attr_reader :type, :proposal, :reference
  STRUCT = [
    [:type, :uint8],
    [:proposal, :select,  ->(ctx){ctx[:type] == Melos::Constants::ProposalOrRefType::PROPOSAL}, :class, Melos::Struct::Proposal],
    [:reference, :select, ->(ctx){ctx[:type] == Melos::Constants::ProposalOrRefType::REFERENCE}, :vec] # ProposalRef is a HashReference, which is a :vec
  ]
end

class Melos::Struct::Commit < Melos::Struct::Base
  attr_reader :proposals, :path
  STRUCT = [
    [:proposals, :classes, Melos::Struct::ProposalOrRef],
    [:path, :optional, Melos::Struct::UpdatePath]
  ]
end

## 12.4.3

class Melos::Struct::GroupInfo < Melos::Struct::Base
  attr_reader :group_context, :extensions, :confirmation_tag, :signer, :signature
  STRUCT = [
    [:group_context, :class, Melos::Struct::GroupContext],
    [:extensions, :classes, Melos::Struct::Extension],
    [:confirmation_tag, :vec], # MAC = opaque <V>
    [:signer, :uint32],
    [:signature, :vec]
  ]

  def group_info_tbs
    Melos::Struct::GroupInfoTBS.create(
      group_context:,
      extensions:,
      confirmation_tag:,
      signer:
    )
  end

  def sign(suite, signer_private)
    Melos::Crypto.sign_with_label(suite, signer_private_key, "GroupInfoTBS", group_info_tbs.raw)
  end

  def verify(suite, signer_public_key)
    Melos::Crypto.verify_with_label(suite, signer_public_key, "GroupInfoTBS", group_info_tbs.raw, signature)
  end
end


class Melos::Struct::GroupInfoTBS < Melos::Struct::Base
  attr_reader :group_context, :extensions, :confirmation_tag, :signer, :signature
  STRUCT = [
    [:group_context, :class, Melos::Struct::GroupContext],
    [:extensions, :classes, Melos::Struct::Extension],
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

class Melos::Struct::PathSecret < Melos::Struct::Base
  attr_reader :path_secret
  STRUCT = [
    [:path_secret, :vec]
  ]
end

class Melos::Struct::GroupSecrets < Melos::Struct::Base
  attr_reader :joiner_secret, :path_secret, :psks
  STRUCT = [
    [:joiner_secret, :vec],
    [:path_secret, :optional, Melos::Struct::PathSecret],
    [:psks, :classes, Melos::Struct::PreSharedKeyID]
  ]
end

class Melos::Struct::EncryptedGroupSecrets < Melos::Struct::Base
  attr_reader :new_member, :encrypted_group_secrets
  STRUCT = [
    [:new_member, :vec], # KeyPackageRef = opaque <V>
    [:encrypted_group_secrets, :class, Melos::Struct::HPKECipherText]
  ]
end

class Melos::Struct::Welcome < Melos::Struct::Base
  attr_reader :cipher_suite, :secrets, :encrypted_group_info
  STRUCT = [
    [:cipher_suite, :uint16],
    [:secrets, :classes, Melos::Struct::EncryptedGroupSecrets],
    [:encrypted_group_info, :vec]
  ]
end

## 12.4.3.2

class Melos::Struct::ExternalPub < Melos::Struct::Base
  attr_reader :external_pub
  STRUCT = [
    [:external_pub, :vec] # HPKEPublicKey
  ]
end

class Melos::Struct::Node < Melos::Struct::Base
  attr_reader :node_type, :leaf_node, :parent_node
  STRUCT = [
    [:node_type, :uint8],
    [:leaf_node,   :select, ->(ctx){ctx[:node_type] == Melos::Constants::NodeType::LEAF},   :class, Melos::Struct::LeafNode], # leaf
    [:parent_node, :select, ->(ctx){ctx[:node_type] == Melos::Constants::NodeType::PARENT}, :class, Melos::Struct::ParentNode] # parent
  ]

  def parent_hash_in_node
    @leaf_node&.parent_hash || @parent_node.parent_hash
  end

  def public_encryption_key
    @leaf_node&.encryption_key || @parent_node&.encryption_key
  end

  def self.new_leaf_node(leaf_node)
    instance = self.allocate
    instance.new_leaf_node_impl(leaf_node)
    instance
  end

  def self.new_parent_node(parent_node)
    instance = self.allocate
    instance.new_parent_node_impl(parent_node)
    instance
  end

  def new_leaf_node_impl(leaf_node)
    @node_type = Melos::Constants::NodeType::LEAF
    @leaf_node = leaf_node
  end

  def new_parent_node_impl(parent_node)
    @node_type = Melos::Constants::NodeType::PARENT
    @parent_node = parent_node
  end
end

# Section 6.1
class Melos::Struct::Sender < Melos::Struct::Base
  attr_reader :sender_type, :leaf_index, :sender_index
  STRUCT = [
    [:sender_type, :uint8],
    [:leaf_index,   :select, ->(ctx){ctx[:sender_type] == Melos::Constants::SenderType::MEMBER}, :uint32],
    [:sender_index, :select, ->(ctx){ctx[:sender_type] == Melos::Constants::SenderType::EXTERNAL}, :uint32],
  ]

  def self.create_member(leaf_index)
    instance = self.allocate
    instance.instance_variable_set(:@sender_type, Melos::Constants::SenderType::MEMBER)
    instance.instance_variable_set(:@leaf_index, leaf_index)
    instance
  end

  def self.create_external(sender_index)
    instance = self.allocate
    instance.instance_variable_set(:@sender_type, Melos::Constants::SenderType::EXTERNAL)
    instance.instance_variable_set(:@sender_index, sender_index)
    instance
  end
end

class Melos::Struct::FramedContentAuthData < Melos::Struct::Base
  attr_reader :signature, :confirmation_tag, :content_type

  STRUCT = [
    [:signature, :vec]
  ]

  # initialize from stream
  def self.new_and_rest_with_content_type(buf, content_type)
    instance = self.allocate
    context, buf = instance.send(:deserialize, buf)
    # custom part based on instance variable
    if content_type == Melos::Constants::ContentType::COMMIT # commit
      # read MAC(opaque <V>) confirmation_tag
      value, buf = Melos::Vec.parse_vec(buf)
      context << [:confirmation_tag, value]
    end
    context << [:content_type, content_type]
    instance.send(:set_instance_vars, context)
    [instance, buf]
  end

  def raw
    if @content_type == Melos::Constants::ContentType::COMMIT
      Melos::Vec.from_string(@signature) + Melos::Vec.from_string(@confirmation_tag)
    else
      Melos::Vec.from_string(@signature)
    end
  end

  def self.create(signature:, content_type:, confirmation_tag:)
    instance = self.allocate
    instance.instance_variable_set(:@signature, signature)
    instance.instance_variable_set(:@content_type, content_type)
    if content_type == Melos::Constants::ContentType::COMMIT
      instance.instance_variable_set(:@confirmation_tag, confirmation_tag)
    end
    instance
  end
end

class Melos::Struct::FramedContent < Melos::Struct::Base
  attr_reader :group_id, :epoch, :sender, :authenticated_data, :content_type, :application_data, :proposal, :commit
  STRUCT = [
    [:group_id, :vec],
    [:epoch, :uint64],
    [:sender, :class, Melos::Struct::Sender],
    [:authenticated_data, :vec],
    [:content_type, :uint8],
    [:application_data, :select, ->(context){context[:content_type] == Melos::Constants::ContentType::APPLICATION}, :vec],
    [:proposal,         :select, ->(context){context[:content_type] == Melos::Constants::ContentType::PROPOSAL}, :class, Melos::Struct::Proposal],
    [:commit,           :select, ->(context){context[:content_type] == Melos::Constants::ContentType::COMMIT}, :class, Melos::Struct::Commit]
  ]

  def content_tbs(version, wire_format, group_context)
    buf = [version].pack('S>') + [wire_format].pack('S>') + self.raw
    case sender.sender_type
    when Melos::Constants::SenderType::MEMBER, Melos::Constants::SenderType::NEW_MEMBER_COMMIT
      buf += group_context.raw
    when Melos::Constants::SenderType::EXTERNAL, Melos::Constants::SenderType::NEW_MEMBER_PROPOSAL
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
    when Melos::Constants::ContentType::APPLICATION
      new_instance.instance_variable_set(:@application_data, content)
    when Melos::Constants::ContentType::PROPOSAL
      new_instance.instance_variable_set(:@proposal, content)
    when Melos::Constants::ContentType::COMMIT
      new_instance.instance_variable_set(:@commit, content)
    end
    new_instance
  end
end

class Melos::Struct::AuthenticatedContent < Melos::Struct::Base
  attr_reader :wire_format, :content, :auth
  STRUCT = [
    [:wire_format, :uint16],
    [:content, :class, Melos::Struct::FramedContent],
    [:auth, :framed_content_auth_data]
  ]

  def content_tbm
    content.content_tbs(Melos::Constants::Version::MLS10, wire_format) + auth.raw
  end

  def confirmed_transcript_hash_input
    Melos::Struct::ConfirmedTranscriptHashInput.create(
      wire_format: wire_format,
      content: content,
      signature: auth.signature
    )
  end

  def verify(suite, signature_public_key, context)
    return false if (wire_format == Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE && content.content_type == Melos::Constants::ContentType::APPLICATION)

    content_tbs = content.content_tbs(Melos::Constants::Version::MLS10, wire_format, context)

    return Melos::Crypto.verify_with_label(suite, signature_public_key, "FramedContentTBS", content_tbs, auth.signature)
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
    raise ArgumentError.new('Application data cannot be sent as a PublicMessage') if wire_format == Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE && content.content_type == Melos::Constants::ContentType::APPLICATION
    content_tbs = content.content_tbs(Melos::Constants::Version::MLS10, wire_format, group_context)
    signature = Melos::Crypto.sign_with_label(suite, signature_private_key, "FramedContentTBS", content_tbs)
    @auth = Melos::Struct::FramedContentAuthData.create(
      signature: signature,
      content_type: content.content_type,
      confirmation_tag: nil
    )
  end
end

## 6.2

class Melos::Struct::PublicMessage < Melos::Struct::Base
  attr_reader :content, :auth, :membership_tag
  STRUCT = [
    [:content, :class, Melos::Struct::FramedContent],
    [:auth, :framed_content_auth_data],
    [:membership_tag, :select, ->(ctx){ctx[:content].sender.sender_type == Melos::Constants::SenderType::MEMBER}, :vec] # MAC is opaque <V>
  ]

  def self.protect(authenticated_content, suite, membership_key, group_context)
    message = self.allocate
    message.instance_variable_set(:@content, authenticated_content.content)
    message.instance_variable_set(:@auth, authenticated_content.auth)
    if message.content.sender.sender_type == Melos::Constants::SenderType::MEMBER # member
      message.instance_variable_set(:@membership_tag, message.membership_mac(suite, membership_key, group_context))
    end
    message
  end

  def unprotect(suite, membership_key, group_context)
    ## if sender type is member then membershipMac(suite, membership_key, group_context)
    if (content.sender.sender_type == Melos::Constants::SenderType::MEMBER)
      return nil if membership_tag != membership_mac(suite, membership_key, group_context)
    end
    Melos::Struct::AuthenticatedContent.create(
      wire_format: Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE, # public_message
      content: content,
      auth: auth
    )
  end

  def membership_mac(suite, membership_key, group_context)
    authenticated_content_tbm = content.content_tbs(
      Melos::Constants::Version::MLS10,
      Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE,
      group_context
    ) + auth.raw
    Melos::Crypto.mac(suite, membership_key, authenticated_content_tbm)
  end
end

## 6.3

class Melos::Struct::PrivateMessage < Melos::Struct::Base
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
    Melos::Vec.from_string(gid) + [ep].pack('Q>') + [ct].pack('C')
  end

  def private_content_aad
    self.class.private_content_aad_impl(group_id, epoch, content_type, authenticated_data)
  end

  def self.private_content_aad_impl(gid, ep, ct, ad)
    Melos::Vec.from_string(gid) + [ep].pack('Q>') + [ct].pack('C') + Melos::Vec.from_string(ad)
  end

  def self.protect(authenticated_content, suite, secret_tree, sender_data_secret, padding_size)
    leaf_index = authenticated_content.content.sender.leaf_index
    content_type = authenticated_content.content.content_type
    reuse_guard = SecureRandom.random_bytes(4)
    key, nonce, generation = Melos::SecretTree::ratchet_and_get(suite, content_type, secret_tree, leaf_index)
    new_nonce = apply_nonce_reuse_guard(nonce, reuse_guard)

    private_message_content_plain = serialize_private_message_content(authenticated_content.content, authenticated_content.auth, padding_size)
    aad = private_content_aad_impl(
      authenticated_content.content.group_id,
      authenticated_content.content.epoch,
      authenticated_content.content.content_type,
      authenticated_content.content.authenticated_data)
    private_message_content_ciphertext = Melos::Crypto.aead_encrypt(suite, key, new_nonce, aad, private_message_content_plain)

    sender_data_plain = Melos::Struct::SenderData.create(
      leaf_index: leaf_index,
      generation: generation,
      reuse_guard: reuse_guard
    )
    sd_aad = sender_data_aad_impl(
      authenticated_content.content.group_id,
      authenticated_content.content.epoch,
      authenticated_content.content.content_type)
    sender_data_key   = Melos::Crypto.sender_data_key(suite, sender_data_secret, private_message_content_ciphertext)
    sender_data_nonce = Melos::Crypto.sender_data_nonce(suite, sender_data_secret, private_message_content_ciphertext)
    sender_data_ciphertext = Melos::Crypto.aead_encrypt(suite, sender_data_key, sender_data_nonce, sd_aad, sender_data_plain.raw)

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
    key, nonce, _ = Melos::SecretTree.ratchet_until_and_get(suite, content_type, secret_tree, sender_data.leaf_index, sender_data.generation)
    new_nonce = self.class.apply_nonce_reuse_guard(nonce, sender_data.reuse_guard)
    pmc, _ = Melos::Struct::PrivateMessageContent.new_and_rest_with_content_type(Melos::Crypto.aead_decrypt(suite, key, new_nonce, private_content_aad, ciphertext), content_type)

    fc = Melos::Struct::FramedContent.create(
      group_id: group_id,
      epoch: epoch,
      sender: Melos::Struct::Sender.create_member(sender_data.leaf_index),
      authenticated_data: authenticated_data,
      content_type: content_type,
      content: pmc.content
    )

    Melos::Struct::AuthenticatedContent.create(
      wire_format: Melos::Constants::WireFormat::MLS_PRIVATE_MESSAGE, # private_message
      content: fc,
      auth: pmc.auth
    )
  end

  private
  def decrypt_sender_data(suite, sender_data_secret)
    sender_data_key   = Melos::Crypto.sender_data_key(suite, sender_data_secret, ciphertext)
    sender_data_nonce = Melos::Crypto.sender_data_nonce(suite, sender_data_secret, ciphertext)
    Melos::Struct::SenderData.new(Melos::Crypto.aead_decrypt(suite, sender_data_key, sender_data_nonce, sender_data_aad, encrypted_sender_data))
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
    when Melos::Constants::ContentType::APPLICATION
      buf += Melos::Vec.from_string(framed_content.application_data)
    when Melos::Constants::ContentType::PROPOSAL
      buf += framed_content.proposal.raw
    when Melos::Constants::ContentType::COMMIT
      buf += framed_content.commit.raw
    end
    buf += Melos::Vec.from_string(framed_content_auth_data.signature)
    if framed_content.content_type == Melos::Constants::ContentType::COMMIT
      buf += Melos::Vec.from_string(framed_content_auth_data.confirmation_tag)
    end
    buf += Melos::Crypto::Util.zero_vector(padding_size)
    buf
  end
end

class Melos::Struct::PrivateMessageContent < Melos::Struct::Base
  attr_accessor :application_data, :proposal, :commit, :auth, :padding
  # bytes -> struct: decode the content and auth field, rest is padding
  # struct -> bytes: encode content and auth field, add set amount of padding (zero bytes)

  def self.new_and_rest_with_content_type(buf, content_type)
    instance = self.allocate
    context = []
    # deserialize application_data/proposal/commit
    case content_type
    when Melos::Constants::ContentType::APPLICATION
      value, buf = Melos::Vec.parse_vec(buf)
      context << [:application_data, value]
    when Melos::Constants::ContentType::PROPOSAL
      value, buf = Melos::Struct::Proposal.new_and_rest(buf)
      context << [:proposal, value]
    when Melos::Constants::ContentType::COMMIT
      value, buf = Melos::Struct::Commit.new_and_rest(buf)
      context << [:commit, value]
    end
    fcad, buf = Melos::Struct::FramedContentAuthData.new_and_rest_with_content_type(buf, content_type)
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

class Melos::Struct::ConfirmedTranscriptHashInput < Melos::Struct::Base
  attr_accessor :wire_format, :content, :signature
  STRUCT = [
    [:wire_format, :uint16],
    [:content, :class, Melos::Struct::FramedContent], # with content_type == commit
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

class Melos::Struct::InterimTranscriptHashInput < Melos::Struct::Base
  attr_reader :confirmation_tag
  STRUCT = [
    [:confirmation_tag, :vec]
  ]
end

class Melos::Struct::MLSMessage < Melos::Struct::Base
  attr_accessor :version, :wire_format, :public_message, :private_message, :welcome, :group_info, :key_package
  STRUCT = [
    [:version, :uint16], #mls10 = 1
    [:wire_format, :uint16],
    [:public_message,  :select, ->(ctx){ctx[:wire_format] == Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE}, :class, Melos::Struct::PublicMessage],
    [:private_message, :select, ->(ctx){ctx[:wire_format] == Melos::Constants::WireFormat::MLS_PRIVATE_MESSAGE}, :class, Melos::Struct::PrivateMessage],
    [:welcome,         :select, ->(ctx){ctx[:wire_format] == Melos::Constants::WireFormat::MLS_WELCOME}, :class, Melos::Struct::Welcome],
    [:group_info,      :select, ->(ctx){ctx[:wire_format] == Melos::Constants::WireFormat::MLS_GROUP_INFO}, :class, Melos::Struct::GroupInfo],
    [:key_package,     :select, ->(ctx){ctx[:wire_format] == Melos::Constants::WireFormat::MLS_KEY_PACKAGE}, :class, Melos::Struct::KeyPackage]
  ]

  def verify(suite, signer_public_key, group_context)
    if wire_format == Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE
      public_message.verify(suite, signer_public_key, version, wire_format, group_context)
    end
  end
end
