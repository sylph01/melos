require 'securerandom'
require_relative 'crypto'
require_relative 'constants'
require_relative 'struct/structs'

# A party outside a group that may send it proposals (RFC 9420 Section 12.1.8): a signature key pair
# and a credential, listed in the group's external_senders GroupContext extension. It holds no group
# state; the caller supplies the group_id and epoch (known from a GroupInfo, say) and its index in
# the extension. Proposals go out as PublicMessages, since an external sender has no epoch secrets.
class Melos::ExternalSender
  attr_reader :suite, :credential

  # signature_private_key: an existing key, or nil to generate one
  def initialize(cipher_suite_id, identity: '', credential: nil, signature_private_key: nil)
    @suite = Melos::Crypto::CipherSuite.new(cipher_suite_id)
    @signature_key_pair = signature_private_key ? @suite.pkey.deserialize_private_signature_key(signature_private_key) : Melos::Crypto.generate_signature_key_pair(@suite)
    @credential = credential || Melos::Struct::Credential.create_basic_credential(identity)
  end

  def signature_private_key
    Melos::Crypto.serialize_private_key(@suite, @signature_key_pair)
  end

  def signature_public_key
    Melos::Crypto.serialize_public_key(@suite, @signature_key_pair)
  end

  # 12.1.8.1: this sender's entry in an external_senders extension
  def external_sender
    Melos::Struct::ExternalSender.create(signature_key: signature_public_key, credential: @credential)
  end

  # 12.1.8: sign and frame a Proposal from this sender, as an MLSMessage carrying a PublicMessage.
  #   sender_index: this sender's position in the group's external_senders extension
  def create_proposal(proposal, group_id:, epoch:, sender_index:, authenticated_data: '')
    unless Melos::Group::EXTERNAL_PROPOSAL_TYPES.include?(proposal.proposal_type)
      raise ArgumentError.new("an external sender cannot send a proposal of type #{proposal.proposal_type}")
    end
    self.class.sign_proposal(@suite, signature_private_key, proposal, Melos::Struct::Sender.create_external(sender_index),
                             group_id: group_id, epoch: epoch, authenticated_data: authenticated_data)
  end

  # 12.1.1: propose adding a member by its KeyPackage (or the MLSMessage carrying it)
  def create_add_proposal(key_package, **options)
    key_package = key_package.key_package if key_package.is_a?(Melos::Struct::MLSMessage)
    create_proposal(Melos::Struct::Proposal.create(proposal_type: Melos::Constants::ProposalType::ADD, add: Melos::Struct::Add.create(key_package: key_package)), **options)
  end

  # 12.1.3: propose removing the member at removed_leaf_index
  def create_remove_proposal(removed_leaf_index, **options)
    create_proposal(Melos::Struct::Proposal.create(proposal_type: Melos::Constants::ProposalType::REMOVE, remove: Melos::Struct::Remove.create(removed: removed_leaf_index)), **options)
  end

  # 12.1.4: propose injecting an external PSK the members know
  def create_psk_proposal(psk_id, **options)
    psk = Melos::Struct::PreSharedKey.create(
      psk: Melos::Struct::PreSharedKeyID.create_external(psk_id: psk_id, psk_nonce: SecureRandom.random_bytes(@suite.kdf.n_h))
    )
    create_proposal(Melos::Struct::Proposal.create(proposal_type: Melos::Constants::ProposalType::PSK, psk: psk), **options)
  end

  # 12.1.7: propose replacing the GroupContext extensions
  def create_group_context_extensions_proposal(extensions, **options)
    gce = Melos::Struct::GroupContextExtensions.create(extensions: extensions)
    create_proposal(Melos::Struct::Proposal.create(proposal_type: Melos::Constants::ProposalType::GROUP_CONTEXT_EXTENSIONS, group_context_extensions: gce), **options)
  end

  # 6.1: a proposal from outside the group, signed without a GroupContext, as a PublicMessage (no membership tag)
  def self.sign_proposal(suite, signature_private_key, proposal, sender, group_id:, epoch:, authenticated_data: '')
    framed_content = Melos::Struct::FramedContent.create(
      group_id: group_id, epoch: epoch, sender: sender, authenticated_data: authenticated_data,
      content_type: Melos::Constants::ContentType::PROPOSAL, content: proposal
    )
    authenticated_content = Melos::Struct::AuthenticatedContent.create(wire_format: Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE, content: framed_content, auth: nil)
    authenticated_content.sign(suite, signature_private_key, nil)
    Melos::Struct::MLSMessage.create(public_message: Melos::Struct::PublicMessage.protect(authenticated_content, suite, nil, nil))
  end
end
