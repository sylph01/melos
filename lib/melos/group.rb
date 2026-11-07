require 'securerandom'
require_relative 'crypto'
require_relative 'constants'
require_relative 'vec'
require_relative 'ratchet_tree'
require_relative 'private_tree'
require_relative 'epoch_secrets'
require_relative 'psk'
require_relative 'struct/structs'

# One member's view of one MLS group (RFC 9420 Sections 8, 11 and 12): the public state every
# member shares (ratchet tree, extensions, transcript hashes, from which the GroupContext is
# derived), this member's private state (leaf index, private tree, signature key) and the
# current epoch's key schedule.
class Melos::Group
  # a member added by a commit: where it landed in the tree, and the KeyPackage it joins with
  Joiner = Struct.new(:leaf_index, :key_package)

  # 12.4.2: the state of the next epoch, computed from a Commit but not yet in effect.
  # It is produced by #stage_commit (received commits) or #create_commit (our own) and applied by #merge_commit.
  # removes_us: the Commit removed this member; only ratchet_tree, extensions, joiners and psk_ids are then set
  StagedCommit = Struct.new(
    :ratchet_tree, :private_tree, :extensions, :confirmed_transcript_hash, :interim_transcript_hash,
    :epoch_secrets, :group_context, :confirmation_tag, :joiners, :path_secrets, :psk_ids, :removes_us,
    keyword_init: true
  )

  # the proposal types defined in RFC 9420; any other type is not supported by this implementation (12.2, 13.2)
  KNOWN_PROPOSAL_TYPES = [
    Melos::Constants::ProposalType::ADD, Melos::Constants::ProposalType::UPDATE, Melos::Constants::ProposalType::REMOVE,
    Melos::Constants::ProposalType::PSK, Melos::Constants::ProposalType::REINIT, Melos::Constants::ProposalType::EXTERNAL_INIT,
    Melos::Constants::ProposalType::GROUP_CONTEXT_EXTENSIONS
  ].freeze

  # what #create_commit produces: the Commit message to send, the Welcome for any joiners (or nil),
  # and the staged state to merge once the Delivery Service has accepted the commit
  CommitResult = Struct.new(:commit, :welcome, :staged, keyword_init: true)

  # 9.1, 15.3: an epoch that is no longer current, kept so its late application messages can be read:
  # its secret tree and sender data secret, and the GroupContext and tree its senders signed against
  PastEpoch = Struct.new(:epoch_secrets, :group_context, :ratchet_tree, keyword_init: true)

  # 15.3: how many epochs before the current one keep their secret trees for late application messages
  DEFAULT_MAX_PAST_EPOCHS = 2

  # 12.1.8: the proposal types an external sender may send; anything else from one is malformed
  EXTERNAL_PROPOSAL_TYPES = [
    Melos::Constants::ProposalType::ADD, Melos::Constants::ProposalType::REMOVE, Melos::Constants::ProposalType::PSK,
    Melos::Constants::ProposalType::REINIT, Melos::Constants::ProposalType::GROUP_CONTEXT_EXTENSIONS
  ].freeze

  # 12.1.8: external proposals that are not authorized are invalid; which ones are is the application's
  # policy. The default accepts every proposal that passes the protocol's own checks.
  DEFAULT_EXTERNAL_PROPOSAL_VALIDATOR = ->(_authenticated_content) { true }

  # the options of .create and .from_welcome that configure the secret tree's ratchets (Melos::SecretTree)
  SECRET_TREE_OPTIONS = %i[max_forward_distance out_of_order_tolerance].freeze

  attr_reader :suite, :group_id, :epoch, :leaf_index, :ratchet_tree, :private_tree, :extensions,
              :confirmed_transcript_hash, :interim_transcript_hash, :epoch_secrets, :resumption_psks, :external_psks

  # Use .create or .from_welcome rather than calling this directly.
  #   credential_validator: ->(credential, leaf_node) { true/false }, the application's Authentication Service check (5.3.1);
  #                         the default accepts basic credentials only
  #   max_leaf_node_lifetime: longest acceptable Lifetime of a leaf node in seconds (7.2); nil for no limit
  #   max_past_epochs: how many earlier epochs still accept application messages (15.3); 0 for none
  #   external_proposal_validator: ->(authenticated_content) { true/false }, whether a proposal from an
  #                                external sender or a new member is authorized (12.1.8)
  # .create and .from_welcome also take max_forward_distance: and out_of_order_tolerance: for the
  # secret tree's ratchets (Melos::SecretTree); epochs created by commits inherit them.
  def initialize(suite:, group_id:, epoch:, leaf_index:, signature_private_key:, ratchet_tree:, private_tree:,
                 extensions:, confirmed_transcript_hash:, interim_transcript_hash:, epoch_secrets:, external_psks: {},
                 credential_validator: DEFAULT_CREDENTIAL_VALIDATOR, max_leaf_node_lifetime: DEFAULT_MAX_LEAF_NODE_LIFETIME,
                 max_past_epochs: DEFAULT_MAX_PAST_EPOCHS, external_proposal_validator: DEFAULT_EXTERNAL_PROPOSAL_VALIDATOR)
    @suite = suite
    @group_id = group_id
    @epoch = epoch
    @leaf_index = leaf_index
    @signature_private_key = signature_private_key
    @ratchet_tree = ratchet_tree
    @private_tree = private_tree
    @extensions = extensions
    @confirmed_transcript_hash = confirmed_transcript_hash
    @interim_transcript_hash = interim_transcript_hash
    @epoch_secrets = epoch_secrets
    @external_psks = external_psks # psk_id -> psk
    @credential_validator = credential_validator
    @max_leaf_node_lifetime = max_leaf_node_lifetime
    @max_past_epochs = max_past_epochs
    @external_proposal_validator = external_proposal_validator
    @past_epochs = {} # epoch -> PastEpoch, for late application messages (9.1, 15.3)
    @resumption_psks = { epoch => epoch_secrets.resumption_psk } # epoch -> resumption_psk (8.4)
    @pending_proposals = {} # ProposalRef -> AuthenticatedContent, sent or received in the current epoch (12.4)
    @pending_updates = {}   # encryption_key -> private key, for Update proposals we sent this epoch (12.1.2)
    @group_context = nil
    @active = true # false once a Commit has removed this member (12.4.2)
  end

  # false after a Commit removed this member: it can no longer send or follow the group,
  # though #unprotect still works for late messages of the last epoch it was in
  def active?
    @active
  end

  # 6: an MLSMessage's version MUST be mls10
  def self.check_message_version!(mls_message)
    return if mls_message.version == Melos::Constants::Version::MLS10
    raise Melos::ProtocolError.new("unsupported MLS version #{mls_message.version}")
  end

  # 11: create a group whose only member is this leaf
  #   external_psks: psk_id -> psk, for external PSKs that commits may reference
  def self.create(suite, group_id, leaf_node, encryption_private_key:, signature_private_key:, extensions: [], external_psks: {}, **options)
    secret_tree_options = options.slice(*SECRET_TREE_OPTIONS)
    options = options.except(*SECRET_TREE_OPTIONS)
    Melos::Struct::Extension.check_unique_types!(extensions, 'GroupContext extensions')
    ratchet_tree = Melos::RatchetTree.new(suite, [Melos::Struct::Node.new_leaf_node(leaf_node)])
    private_tree = Melos::PrivateTree.new
    private_tree[0] = encryption_private_key
    group_context = Melos::Struct::GroupContext.create(
      cipher_suite: suite.suite_id, group_id: group_id, epoch: 0,
      tree_hash: ratchet_tree.root_tree_hash, confirmed_transcript_hash: '', extensions: extensions
    )
    # 8: epoch 0 is derived from a fresh random init_secret, an all-zero commit secret and no PSKs
    epoch_secrets = Melos::EpochSecrets.from_init_secret(suite, SecureRandom.random_bytes(suite.kdf.n_h), secret_tree_options: secret_tree_options)
      .next(Melos::Crypto::Util.zero_vector(suite.kdf.n_h), Melos::PSK.psk_secret(suite, []), group_context, n_leaves: 1)
    confirmation_tag = Melos::Crypto.mac(suite, epoch_secrets.confirmation_key, '')
    new(
      suite: suite, group_id: group_id, epoch: 0, leaf_index: 0, signature_private_key: signature_private_key,
      ratchet_tree: ratchet_tree, private_tree: private_tree, extensions: extensions,
      confirmed_transcript_hash: '', interim_transcript_hash: interim_transcript_hash(suite, '', confirmation_tag),
      epoch_secrets: epoch_secrets.discard_consumed!, external_psks: external_psks, **options
    )
  end

  # 12.4.3.1: join a group from a Welcome.
  #   welcome: a Melos::Struct::MLSMessage carrying a Welcome, or the Welcome itself
  #   key_package: the KeyPackage (or MLSMessage carrying it) this member published
  #   init_private_key, encryption_private_key: private keys of the KeyPackage's init_key and leaf encryption_key
  #   external_psks: psk_id -> psk, for any external PSKs the Welcome references
  #   ratchet_tree: serialized tree, if it was delivered outside the Welcome's ratchet_tree extension
  def self.from_welcome(suite, welcome, key_package:, init_private_key:, encryption_private_key:, signature_private_key:,
                        external_psks: {}, ratchet_tree: nil, **options)
    secret_tree_options = options.slice(*SECRET_TREE_OPTIONS)
    options = options.except(*SECRET_TREE_OPTIONS)
    if welcome.is_a?(Melos::Struct::MLSMessage)
      check_message_version!(welcome)
      welcome = welcome.welcome
    end
    raise ArgumentError.new('not a Welcome message') if welcome.nil?
    raise Melos::ProtocolError.new('Welcome is for a different cipher suite') unless welcome.cipher_suite == suite.suite_id
    key_package = key_package.key_package if key_package.is_a?(Melos::Struct::MLSMessage)
    # 12.4.3.1: the KeyPackage and the Welcome must be for the same cipher suite
    raise Melos::ProtocolError.new('KeyPackage and Welcome are for different cipher suites') unless key_package.cipher_suite == welcome.cipher_suite

    # Identify the entry in welcome.secrets corresponding to our KeyPackage and decrypt it with init_priv
    key_package_ref = key_package.ref(suite)
    encrypted_group_secrets = welcome.secrets.find { _1.new_member == key_package_ref }&.encrypted_group_secrets
    raise Melos::ProtocolError.new('Welcome has no entry for this KeyPackage') if encrypted_group_secrets.nil?
    group_secrets = Melos::Struct::GroupSecrets.new(
      Melos::Crypto.decrypt_with_label(
        suite, init_private_key, "Welcome", welcome.encrypted_group_info,
        encrypted_group_secrets.kem_output, encrypted_group_secrets.ciphertext
      )
    )

    # 8.4: the PSKs named in GroupSecrets
    # TODO: resumption PSKs in a Welcome (reinit, branch)
    psks = group_secrets.psks.map do |psk_id|
      raise Melos::UnsupportedError.new('unsupported PSK type in Welcome') unless psk_id.psktype == Melos::Constants::PSKType::EXTERNAL
      [psk_id.raw, external_psks.fetch(psk_id.psk_id) { raise Melos::StateError.new('Welcome references an unknown external PSK') }]
    end
    psk_secret = Melos::PSK.psk_secret(suite, psks)

    # Decrypt the GroupInfo
    welcome_key, welcome_nonce = Melos::EpochSecrets.welcome_key_and_nonce(suite, group_secrets.joiner_secret, psk_secret)
    group_info = Melos::Struct::GroupInfo.new(
      Melos::Crypto.aead_decrypt(suite, welcome_key, welcome_nonce, "", welcome.encrypted_group_info)
    )
    group_context = group_info.group_context
    raise Melos::ProtocolError.new("unsupported MLS version #{group_context.version} in GroupContext") unless group_context.version == Melos::Constants::Version::MLS10
    raise Melos::ProtocolError.new('GroupInfo is for a different cipher suite') unless group_context.cipher_suite == suite.suite_id
    Melos::Struct::Extension.check_unique_types!(group_context.extensions, 'GroupContext extensions')
    Melos::Struct::Extension.check_unique_types!(group_info.extensions, 'GroupInfo extensions')

    # The ratchet tree: delivered out of band, or in the GroupInfo's ratchet_tree extension
    ratchet_tree_data = ratchet_tree || group_info.extensions.find { _1.extension_type == Melos::Constants::ExtensionType::RATCHET_TREE }&.extension_data
    raise ArgumentError.new('no ratchet tree available') if ratchet_tree_data.nil?
    tree = Melos::RatchetTree.parse(suite, ratchet_tree_data)
    raise Melos::ProtocolError.new('tree hash does not match GroupContext') unless tree.root_tree_hash == group_context.tree_hash

    # Verify the GroupInfo signature with the signer's leaf
    signer_leaf_node = tree.leaf_node_at(group_info.signer)
    raise Melos::ProtocolError.new('GroupInfo signer is not in the tree') if signer_leaf_node.nil?
    raise Melos::ProtocolError.new('GroupInfo signature does not verify') unless group_info.verify(suite, signer_leaf_node.signature_key)

    # Find our own leaf: the one identical to our KeyPackage's LeafNode
    leaf_index = tree.find_leaf_index { _1.raw == key_package.leaf_node.raw }
    raise Melos::ProtocolError.new('our KeyPackage is not in the tree') if leaf_index.nil?
    private_tree = Melos::PrivateTree.new
    private_tree[leaf_index * 2] = encryption_private_key
    # 12.4.3.1: a path secret in GroupSecrets is that of the common ancestor of our leaf and the signer's
    if group_secrets.path_secret
      common_ancestor = Melos::Tree.common_ancestor_semantic(leaf_index * 2, group_info.signer * 2, tree.n_leaves)
      private_tree.set_path_secret(tree, common_ancestor, group_secrets.path_secret.path_secret)
    end

    # Enter the epoch's key schedule and check the GroupInfo's confirmation tag against it
    epoch_secrets = Melos::EpochSecrets.from_joiner(suite, group_secrets.joiner_secret, psk_secret, group_context, n_leaves: tree.n_leaves,
                                                    secret_tree_options: secret_tree_options)
    expected_tag = Melos::Crypto.mac(suite, epoch_secrets.confirmation_key, group_context.confirmed_transcript_hash)
    raise Melos::ProtocolError.new('GroupInfo confirmation tag does not verify') unless group_info.confirmation_tag == expected_tag

    group = new(
      suite: suite, group_id: group_context.group_id, epoch: group_context.epoch, leaf_index: leaf_index,
      signature_private_key: signature_private_key, ratchet_tree: tree, private_tree: private_tree,
      extensions: group_context.extensions, confirmed_transcript_hash: group_context.confirmed_transcript_hash,
      interim_transcript_hash: interim_transcript_hash(suite, group_context.confirmed_transcript_hash, group_info.confirmation_tag),
      epoch_secrets: epoch_secrets, external_psks: external_psks, **options
    )
    group.send(:validate_joined_state!)
    epoch_secrets.discard_consumed! # 9.2: the joiner secret has done its work
    group
  end

  # 8.2: interim_transcript_hash = Hash(confirmed_transcript_hash || InterimTranscriptHashInput)
  def self.interim_transcript_hash(suite, confirmed_transcript_hash, confirmation_tag)
    Melos::Crypto.hash(suite, confirmed_transcript_hash + Melos::Vec.string_to_vec(confirmation_tag))
  end

  # 8.1: the GroupContext of the current epoch
  def group_context
    @group_context ||= Melos::Struct::GroupContext.create(
      cipher_suite: @suite.suite_id, group_id: @group_id, epoch: @epoch,
      tree_hash: @ratchet_tree.root_tree_hash, confirmed_transcript_hash: @confirmed_transcript_hash, extensions: @extensions
    )
  end

  def epoch_authenticator
    @epoch_secrets.epoch_authenticator
  end

  # 8.5: a secret derived from this epoch for the application's own use; every member gets the same value
  def export_secret(label, context, length)
    @epoch_secrets.export(label, context, length)
  end

  ## Persistence

  # version of the Hash produced by #to_h
  STATE_FORMAT = 1

  # The whole state of this member's view of the group, as a Hash whose keys are Symbols and whose values are
  # binary Strings, Integers, true/false/nil, Arrays and such Hashes: secrets, private keys and ratchet
  # positions included, so a restored group never reuses a nonce (6.3.1). Store it encrypted; that is
  # the application's job. Melos::Persistence turns it into JSON.
  # The credential_validator and external_proposal_validator procs are not included: pass them to .from_h again.
  #   include_external_psks: false when the PSKs are kept elsewhere (Melos::Client does)
  def to_h(include_external_psks: true)
    {
      format: STATE_FORMAT,
      cipher_suite: @suite.suite_id, group_id: @group_id, epoch: @epoch, leaf_index: @leaf_index,
      signature_private_key: @signature_private_key,
      ratchet_tree: @ratchet_tree.raw, private_tree: @private_tree.to_a,
      extensions: @extensions.map(&:raw),
      confirmed_transcript_hash: @confirmed_transcript_hash, interim_transcript_hash: @interim_transcript_hash,
      epoch_secrets: @epoch_secrets.to_h,
      resumption_psks: @resumption_psks.to_a,
      external_psks: include_external_psks ? @external_psks.to_a : nil,
      pending_proposals: @pending_proposals.map { |ref, authenticated_content| [ref, authenticated_content.raw] },
      pending_updates: @pending_updates.to_a,
      past_epochs: @past_epochs.map do |epoch, past|
        [epoch, { epoch_secrets: past.epoch_secrets.to_h, group_context: past.group_context.raw, ratchet_tree: past.ratchet_tree.raw }]
      end,
      active: @active,
      max_leaf_node_lifetime: @max_leaf_node_lifetime, max_past_epochs: @max_past_epochs
    }
  end

  # A group from #to_h.
  #   external_psks: the Hash to share with the restored group (a Client passes its own); defaults to the saved ones
  #   options: credential_validator:, external_proposal_validator:, as for .create
  def self.from_h(hash, external_psks: nil, **options)
    raise ArgumentError.new("unknown group state format #{hash[:format]}") unless hash[:format] == STATE_FORMAT
    suite = Melos::Crypto::CipherSuite.new(hash[:cipher_suite])
    group = new(
      suite: suite, group_id: hash[:group_id], epoch: hash[:epoch], leaf_index: hash[:leaf_index],
      signature_private_key: hash[:signature_private_key],
      ratchet_tree: Melos::RatchetTree.parse(suite, hash[:ratchet_tree]), private_tree: Melos::PrivateTree.from_a(hash[:private_tree]),
      extensions: hash[:extensions].map { Melos::Struct::Extension.new(_1) },
      confirmed_transcript_hash: hash[:confirmed_transcript_hash], interim_transcript_hash: hash[:interim_transcript_hash],
      epoch_secrets: Melos::EpochSecrets.from_h(suite, hash[:epoch_secrets]),
      external_psks: external_psks || (hash[:external_psks] || []).to_h,
      max_leaf_node_lifetime: hash[:max_leaf_node_lifetime], max_past_epochs: hash[:max_past_epochs], **options
    )
    group.send(:restore_state, hash)
    group
  end

  ## Receiving messages (6, 12.4)

  # Unprotect an MLSMessage sent in this group and verify its signature. Handshake messages must be
  # from the current epoch; application messages may also come from one of the last max_past_epochs
  # epochs (9.1, 15.3), and are then checked against that epoch's secrets, tree and GroupContext.
  # Returns the Melos::Struct::AuthenticatedContent.
  def unprotect(mls_message)
    self.class.check_message_version!(mls_message)
    epoch_secrets, context, tree = @epoch_secrets, group_context, @ratchet_tree
    authenticated_content =
      case mls_message.wire_format
      when Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE
        mls_message.public_message.unprotect(@suite, @epoch_secrets.membership_key, group_context) or
          raise Melos::ProtocolError.new('membership tag does not verify')
      when Melos::Constants::WireFormat::MLS_PRIVATE_MESSAGE
        private_message = mls_message.private_message
        raise Melos::ProtocolError.new('message is for a different group') unless private_message.group_id == @group_id
        if private_message.epoch != @epoch
          past = @past_epochs[private_message.epoch] if private_message.content_type == Melos::Constants::ContentType::APPLICATION
          raise Melos::ProtocolError.new("message is for epoch #{private_message.epoch}, current epoch is #{@epoch}") if past.nil?
          epoch_secrets, context, tree = past.epoch_secrets, past.group_context, past.ratchet_tree
        end
        private_message.unprotect(@suite, epoch_secrets.secret_tree, epoch_secrets.sender_data_secret)
      else
        raise ArgumentError.new('not a PublicMessage or PrivateMessage')
      end
    content = authenticated_content.content
    raise Melos::ProtocolError.new('message is for a different group') unless content.group_id == @group_id
    raise Melos::ProtocolError.new("message is for epoch #{content.epoch}, current epoch is #{@epoch}") unless content.epoch == context.epoch
    validate_non_member_content!(authenticated_content) unless content.sender.sender_type == Melos::Constants::SenderType::MEMBER
    raise Melos::ProtocolError.new('signature does not verify') unless authenticated_content.verify(@suite, sender_signature_key(content, tree), context)
    authenticated_content
  end

  # 12.1.8.1: the senders the external_senders GroupContext extension allows, as Melos::Struct::ExternalSender (empty without it)
  def external_senders(extensions = @extensions)
    extension = extensions.find { _1.extension_type == Melos::Constants::ExtensionType::EXTERNAL_SENDERS }
    extension ? Melos::Struct::ExternalSenders.new(extension.extension_data).external_senders : []
  end

  # the earlier epochs whose application messages are still accepted, oldest first
  def past_epochs
    @past_epochs.keys
  end

  # Unprotect a message and act on it: cache a proposal, apply a commit, hand back application data.
  # Returns the Melos::Struct::AuthenticatedContent in every case. A removed member cannot use this;
  # it may still call #unprotect for late messages of the last epoch it was in.
  def process_message(mls_message)
    ensure_active!
    authenticated_content = unprotect(mls_message)
    case authenticated_content.content.content_type
    when Melos::Constants::ContentType::PROPOSAL
      process_proposal(authenticated_content)
    when Melos::Constants::ContentType::COMMIT
      process_commit(authenticated_content)
    end
    authenticated_content
  end

  # 12.4: remember a proposal of this epoch so a Commit can reference it
  def process_proposal(authenticated_content)
    ensure_active!
    raise ArgumentError.new('not a proposal') unless authenticated_content.content.content_type == Melos::Constants::ContentType::PROPOSAL
    @pending_proposals[Melos::Crypto.make_proposal_ref(@suite, authenticated_content.raw)] = authenticated_content
  end

  def process_commit(authenticated_content)
    merge_commit(stage_commit(authenticated_content))
  end

  # 12.4.2: compute the next epoch's state from a received Commit without changing this group yet
  def stage_commit(authenticated_content)
    stage(authenticated_content, own_path: nil)
  end

  # 12.4.2: make a staged commit the current state; the group moves to the next epoch.
  # If the commit removed this member, the group becomes inactive instead: it keeps the secrets of
  # the last epoch it was in so late messages can still be read, but nothing more can be sent or processed.
  def merge_commit(staged)
    if staged.removes_us
      @active = false
      @pending_proposals = {}
      return self
    end
    retain_past_epoch!
    @ratchet_tree = staged.ratchet_tree
    @private_tree = staged.private_tree
    @extensions = staged.extensions
    @confirmed_transcript_hash = staged.confirmed_transcript_hash
    @interim_transcript_hash = staged.interim_transcript_hash
    @epoch_secrets = staged.epoch_secrets
    @epoch += 1
    # 9.2, 7.5: the previous epoch's secrets go with the previous EpochSecrets; the new epoch keeps only
    # what it still needs, and the private tree keeps only keys for nodes that still carry them
    @epoch_secrets.discard_consumed!
    @private_tree.prune!(@ratchet_tree)
    staged.path_secrets = nil
    @group_context = nil
    @pending_proposals = {}
    @pending_updates = {}
    @resumption_psks[@epoch] = @epoch_secrets.resumption_psk
    self
  end

  ## Sending messages (6)

  # Frame, sign and protect content for the wire in the current epoch. Returns a Melos::Struct::MLSMessage.
  #   content_type: Melos::Constants::ContentType; content: application data (String), Proposal or Commit
  def protect(content_type, content, wire_format: Melos::Constants::WireFormat::MLS_PRIVATE_MESSAGE, authenticated_data: '', padding_size: 0)
    ensure_active!
    protect_authenticated_content(frame_and_sign(content_type, content, wire_format: wire_format, authenticated_data: authenticated_data), padding_size: padding_size)
  end

  # 6.1: application data is always sent as a PrivateMessage.
  # 12.4: a member that has seen proposals in this epoch MUST commit them before sending application data.
  def create_application_message(data, authenticated_data: '', padding_size: 0)
    raise Melos::StateError.new('proposals are pending in this epoch; commit them before sending application data') unless @pending_proposals.empty?
    protect(Melos::Constants::ContentType::APPLICATION, data,
            wire_format: Melos::Constants::WireFormat::MLS_PRIVATE_MESSAGE, authenticated_data: authenticated_data, padding_size: padding_size)
  end

  # 12.1: send a Proposal; it is also remembered here so that our own Commit can reference it
  def create_proposal(proposal, wire_format: Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE, authenticated_data: '', padding_size: 0)
    authenticated_content = frame_and_sign(Melos::Constants::ContentType::PROPOSAL, proposal, wire_format: wire_format, authenticated_data: authenticated_data)
    process_proposal(authenticated_content)
    protect_authenticated_content(authenticated_content, padding_size: padding_size)
  end

  # 12.1.1: key_package is the new member's KeyPackage, or the MLSMessage carrying it
  def create_add_proposal(key_package, **options)
    if key_package.is_a?(Melos::Struct::MLSMessage)
      self.class.check_message_version!(key_package)
      # 10: a KeyPackage carried in an MLSMessage MUST have the same version as the message
      raise Melos::ProtocolError.new('KeyPackage version differs from its MLSMessage') unless key_package.key_package.version == key_package.version
      key_package = key_package.key_package
    end
    validate_key_package!(key_package, tree: @ratchet_tree, leaf_index: nil, extensions: @extensions, sending: true)
    add = Melos::Struct::Add.create(key_package: key_package)
    create_proposal(Melos::Struct::Proposal.create(proposal_type: Melos::Constants::ProposalType::ADD, add: add), **options)
  end

  # 12.1.2: propose replacing our leaf with one carrying a fresh encryption key, and optionally new
  # capabilities or extensions. The new private key is kept until a commit applies the Update; it
  # takes effect in #merge_commit. Our own commit never references our Update (12.2): its UpdatePath
  # replaces the leaf anyway.
  def create_update_proposal(capabilities: nil, extensions: nil, **options)
    ensure_active!
    current = @ratchet_tree.leaf_node_at(@leaf_index)
    key_pair = Melos::Crypto.generate_encapsulation_key_pair(@suite)
    leaf_node = Melos::Struct::LeafNode.create(
      encryption_key: Melos::Crypto.serialize_public_key(@suite, key_pair),
      signature_key: current.signature_key,
      credential: current.credential,
      capabilities: capabilities || current.capabilities,
      leaf_node_source: Melos::Constants::LeafNodeSource::UPDATE,
      lifetime: nil,
      parent_hash: nil,
      extensions: extensions || current.extensions,
      signature: nil
    )
    leaf_node.sign(@suite, @signature_private_key, @group_id, @leaf_index)
    validate_leaf_node!(leaf_node, context: :update, leaf_index: @leaf_index, tree: @ratchet_tree, extensions: @extensions, replacing: current, sending: true)
    @pending_updates[leaf_node.encryption_key] = Melos::Crypto.serialize_private_key(@suite, key_pair)
    update = Melos::Struct::Update.create(leaf_node: leaf_node)
    create_proposal(Melos::Struct::Proposal.create(proposal_type: Melos::Constants::ProposalType::UPDATE, update: update), **options)
  end

  # 12.1.3
  def create_remove_proposal(removed_leaf_index, **options)
    raise ArgumentError.new("leaf #{removed_leaf_index} is blank") if @ratchet_tree.leaf_node_at(removed_leaf_index).nil?
    remove = Melos::Struct::Remove.create(removed: removed_leaf_index)
    create_proposal(Melos::Struct::Proposal.create(proposal_type: Melos::Constants::ProposalType::REMOVE, remove: remove), **options)
  end

  # 12.1.4 / 8.4: inject the external PSK psk_id, which every member must know, into the next epoch
  def create_psk_proposal(psk_id, **options)
    raise ArgumentError.new('unknown external PSK') unless @external_psks.key?(psk_id)
    psk = Melos::Struct::PreSharedKey.create(
      psk: Melos::Struct::PreSharedKeyID.create_external(psk_id: psk_id, psk_nonce: SecureRandom.random_bytes(@suite.kdf.n_h))
    )
    create_proposal(Melos::Struct::Proposal.create(proposal_type: Melos::Constants::ProposalType::PSK, psk: psk), **options)
  end

  # 12.4: commit the proposals of this epoch (those sent or received, by reference, plus inline_proposals by value).
  # Returns a CommitResult; call #merge_commit(result.staged) once the Delivery Service has accepted the commit,
  # and send result.welcome to the new members if there are any.
  #   path: :always includes a fresh UpdatePath (post-compromise security for the committer);
  #         :if_required leaves it out when 12.4 allows, i.e. the list is non-empty and has no path-required proposal
  def create_commit(inline_proposals: [], wire_format: Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE, authenticated_data: '',
                    padding_size: 0, include_ratchet_tree: true, path: :always)
    ensure_active!
    raise ArgumentError.new('path must be :always or :if_required') unless %i[always if_required].include?(path)
    # 12.2: a commit must not include an Update from the committer, so ours are left out (the path replaces our leaf)
    referenced = @pending_proposals.reject { |_ref, authenticated_content| own_update?(authenticated_content) }
    proposal_or_refs =
      referenced.keys.map { Melos::Struct::ProposalOrRef.create(type: Melos::Constants::ProposalOrRefType::REFERENCE, proposal: nil, reference: _1) } +
      inline_proposals.map { Melos::Struct::ProposalOrRef.create(type: Melos::Constants::ProposalOrRefType::PROPOSAL, proposal: _1, reference: nil) }
    proposals = resolve_proposals(proposal_or_refs, @leaf_index)
    validate_proposal_list!(proposals, @leaf_index)

    # 12.4.2: the UpdatePath is built on the tree after the proposals, and not encrypted to the leaves being added
    tree = @ratchet_tree.dup
    private_tree = @private_tree.dup
    extensions, joiners, _psk_ids = apply_proposals(tree, proposals, sending: true)
    if path == :always || path_required?(proposals)
      provisional_group_context = Melos::Struct::GroupContext.create(
        cipher_suite: @suite.suite_id, group_id: @group_id, epoch: @epoch + 1,
        tree_hash: '', confirmed_transcript_hash: @confirmed_transcript_hash, extensions: extensions # tree_hash is filled in by create_update_path
      )
      update = tree.create_update_path(private_tree, @leaf_index, @signature_private_key, provisional_group_context, joiners.map { _1.leaf_index * 2 })
      own_path = { private_tree: private_tree, commit_secret: update[:commit_secret], path_secrets: update[:path_secrets] }
    else
      # 12.4.1: no path, so the commit secret is all zeros and our keys stay as they are
      update = { update_path: nil }
      own_path = { private_tree: private_tree, commit_secret: Melos::Crypto::Util.zero_vector(@suite.kdf.n_h), path_secrets: nil }
    end

    commit = Melos::Struct::Commit.create(proposals: proposal_or_refs, path: update[:update_path])
    authenticated_content = frame_and_sign(Melos::Constants::ContentType::COMMIT, commit, wire_format: wire_format, authenticated_data: authenticated_data)
    staged = stage(authenticated_content, own_path: own_path)
    authenticated_content.auth.confirmation_tag = staged.confirmation_tag

    result = CommitResult.new(
      commit: protect_authenticated_content(authenticated_content, padding_size: padding_size),
      welcome: staged.joiners.empty? ? nil : create_welcome(staged, include_ratchet_tree: include_ratchet_tree),
      staged: staged
    )
    staged.path_secrets = nil # 9.2: used for the Welcome, not needed again
    result
  end

  # 12.4.3.1: the Welcome for the members a staged commit adds
  def create_welcome(staged, include_ratchet_tree: true)
    extensions = []
    extensions << Melos::Struct::Extension.create(extension_type: Melos::Constants::ExtensionType::RATCHET_TREE, extension_data: staged.ratchet_tree.raw) if include_ratchet_tree
    group_info = Melos::Struct::GroupInfo.create(
      group_context: staged.group_context, extensions: extensions, confirmation_tag: staged.confirmation_tag, signer: @leaf_index, signature: nil
    )
    group_info.sign(@suite, @signature_private_key)
    welcome_key, welcome_nonce = staged.epoch_secrets.welcome_key_and_nonce
    encrypted_group_info = Melos::Crypto.aead_encrypt(@suite, welcome_key, welcome_nonce, "", group_info.raw)

    secrets = staged.joiners.map do |joiner|
      path_secret = nil
      if staged.path_secrets
        # the joiner gets the path secret of the node where its direct path meets ours
        common_ancestor = Melos::Tree.common_ancestor_semantic(joiner.leaf_index * 2, @leaf_index * 2, staged.ratchet_tree.n_leaves)
        path_secret = Melos::Struct::PathSecret.create(path_secret: staged.path_secrets.fetch(common_ancestor))
      end
      group_secrets = Melos::Struct::GroupSecrets.create(joiner_secret: staged.epoch_secrets.joiner_secret, path_secret: path_secret, psks: staged.psk_ids)
      kem_output, ciphertext = Melos::Crypto.encrypt_with_label(@suite, joiner.key_package.init_key, "Welcome", encrypted_group_info, group_secrets.raw)
      Melos::Struct::EncryptedGroupSecrets.create(
        new_member: joiner.key_package.ref(@suite),
        encrypted_group_secrets: Melos::Struct::HPKECipherText.create(kem_output: kem_output, ciphertext: ciphertext)
      )
    end
    welcome = Melos::Struct::Welcome.create(cipher_suite: @suite.suite_id, secrets: secrets, encrypted_group_info: encrypted_group_info)
    Melos::Struct::MLSMessage.create(welcome: welcome)
  end

  private

  # 12.4.2: the next epoch's state from a Commit.
  #   own_path: when we are the committer, { private_tree:, commit_secret:, path_secrets: } from create_update_path;
  #             the confirmation tag is then computed rather than verified
  def stage(authenticated_content, own_path:)
    ensure_active!
    content = authenticated_content.content
    raise ArgumentError.new('not a commit') unless content.content_type == Melos::Constants::ContentType::COMMIT
    raise Melos::ProtocolError.new("commit is for epoch #{content.epoch}, current epoch is #{@epoch}") unless content.epoch == @epoch
    # TODO: external and new-member commits
    raise Melos::UnsupportedError.new('only commits from members are supported') unless content.sender.sender_type == Melos::Constants::SenderType::MEMBER
    committer = content.sender.leaf_index
    raise ArgumentError.new('our own commit must be staged through create_commit') if committer == @leaf_index && own_path.nil?
    commit = content.commit

    proposals = resolve_proposals(commit.proposals, committer)
    validate_proposal_list!(proposals, committer)
    raise Melos::ProtocolError.new('commit must have a path') if commit.path.nil? && path_required?(proposals)

    tree = @ratchet_tree.dup
    private_tree = own_path ? own_path[:private_tree] : @private_tree.dup
    extensions, joiners, psk_ids = apply_proposals(tree, proposals, sending: !own_path.nil?)

    # 12.4.2: a commit may remove us; we cannot follow it any further, since the path is not encrypted to us.
    # Our leaf index may be non-blank afterwards if an Add in the same commit reused it, so look at the Removes themselves.
    removes_us = proposals.any? { |proposal, _sender| proposal.proposal_type == Melos::Constants::ProposalType::REMOVE && proposal.remove.removed == @leaf_index }
    if removes_us
      return StagedCommit.new(ratchet_tree: tree, extensions: extensions, joiners: joiners, psk_ids: psk_ids, removes_us: true)
    end
    # if this commit applied an Update of ours, the UpdatePath below is encrypted to our new leaf key
    adopt_pending_update!(tree, private_tree)

    if commit.path.nil?
      commit_secret = Melos::Crypto::Util.zero_vector(@suite.kdf.n_h)
    else
      validate_update_path!(tree, commit.path, committer, joiners, extensions) unless own_path
      tree.merge_update_path(committer, commit.path)
      if own_path
        commit_secret = own_path[:commit_secret]
      else
        # the UpdatePath is encrypted with the provisional GroupContext: new epoch and tree, old transcript hash
        provisional_group_context = Melos::Struct::GroupContext.create(
          cipher_suite: @suite.suite_id, group_id: @group_id, epoch: @epoch + 1,
          tree_hash: tree.root_tree_hash, confirmed_transcript_hash: @confirmed_transcript_hash, extensions: extensions
        )
        path_secret = tree.decrypt_path_secret(private_tree, commit.path, committer, @leaf_index, provisional_group_context, joiners.map(&:leaf_index))
        commit_secret = tree.calculate_commit_secret(commit.path, committer, @leaf_index, path_secret)
      end
    end

    # 8.2: transcript hashes
    confirmed_transcript_hash = Melos::Crypto.hash(@suite, @interim_transcript_hash + authenticated_content.confirmed_transcript_hash_input.raw)
    new_group_context = Melos::Struct::GroupContext.create(
      cipher_suite: @suite.suite_id, group_id: @group_id, epoch: @epoch + 1,
      tree_hash: tree.root_tree_hash, confirmed_transcript_hash: confirmed_transcript_hash, extensions: extensions
    )

    # 8: the next epoch's key schedule, and the confirmation tag that goes with it
    epoch_secrets = @epoch_secrets.next(commit_secret, psk_secret_for(psk_ids), new_group_context, n_leaves: tree.n_leaves)
    confirmation_tag = Melos::Crypto.mac(@suite, epoch_secrets.confirmation_key, confirmed_transcript_hash)
    if own_path.nil? && authenticated_content.auth.confirmation_tag != confirmation_tag
      raise Melos::ProtocolError.new('confirmation tag does not verify')
    end

    StagedCommit.new(
      ratchet_tree: tree, private_tree: private_tree, extensions: extensions,
      confirmed_transcript_hash: confirmed_transcript_hash,
      interim_transcript_hash: self.class.interim_transcript_hash(@suite, confirmed_transcript_hash, confirmation_tag),
      epoch_secrets: epoch_secrets, group_context: new_group_context, confirmation_tag: confirmation_tag,
      joiners: joiners, path_secrets: own_path && own_path[:path_secrets], psk_ids: psk_ids
    )
  end

  # 9.1, 15.3: as the group leaves the current epoch, keep what its late application messages need,
  # and forget epochs older than max_past_epochs (9.2: their secrets are then deleted)
  def retain_past_epoch!
    if @max_past_epochs.positive?
      @past_epochs[@epoch] = PastEpoch.new(
        epoch_secrets: @epoch_secrets.retain_for_past_messages!, group_context: group_context, ratchet_tree: @ratchet_tree
      )
    end
    @past_epochs.delete_if { |epoch, _| epoch <= @epoch - @max_past_epochs }
  end

  # the parts of #to_h that .new does not take
  def restore_state(hash)
    @resumption_psks = hash[:resumption_psks].to_h
    @pending_proposals = hash[:pending_proposals].to_h { |ref, raw| [ref, Melos::Struct::AuthenticatedContent.new(raw)] }
    @pending_updates = hash[:pending_updates].to_h
    @past_epochs = hash[:past_epochs].to_h do |epoch, past|
      [epoch, PastEpoch.new(
        epoch_secrets: Melos::EpochSecrets.from_h(@suite, past[:epoch_secrets]),
        group_context: Melos::Struct::GroupContext.new(past[:group_context]),
        ratchet_tree: Melos::RatchetTree.parse(@suite, past[:ratchet_tree])
      )]
    end
    @active = hash[:active]
  end

  def ensure_active!
    raise Melos::StateError.new("this member was removed from the group in epoch #{@epoch}") unless @active
  end

  # an Update proposal sent by this member
  def own_update?(authenticated_content)
    content = authenticated_content.content
    content.content_type == Melos::Constants::ContentType::PROPOSAL &&
      content.proposal.proposal_type == Melos::Constants::ProposalType::UPDATE &&
      content.sender.sender_type == Melos::Constants::SenderType::MEMBER && content.sender.leaf_index == @leaf_index
  end

  # 12.1.2: if our leaf in tree now carries the key of an Update we sent, install the private key we kept for it
  def adopt_pending_update!(tree, private_tree)
    private_key = @pending_updates[tree.leaf_node_at(@leaf_index)&.encryption_key]
    private_tree[@leaf_index * 2] = private_key if private_key
  end

  # 12.4: a commit's path is required if its proposal list is empty or contains a path-required type
  def path_required?(proposals)
    proposals.empty? || proposals.any? do |proposal, _sender|
      [Melos::Constants::ProposalType::UPDATE, Melos::Constants::ProposalType::REMOVE,
       Melos::Constants::ProposalType::EXTERNAL_INIT, Melos::Constants::ProposalType::GROUP_CONTEXT_EXTENSIONS].include?(proposal.proposal_type)
    end
  end

  # 6.1: the key that signed this FramedContent, by its sender type; members are looked up in tree
  def sender_signature_key(content, tree = @ratchet_tree)
    sender = content.sender
    case sender.sender_type
    when Melos::Constants::SenderType::MEMBER
      leaf_node = tree.leaf_node_at(sender.leaf_index)
      raise Melos::ProtocolError.new("sender leaf #{sender.leaf_index} is blank") if leaf_node.nil?
      leaf_node.signature_key
    when Melos::Constants::SenderType::EXTERNAL
      # 12.1.8: only with the external_senders extension, by index into it
      external_sender = external_senders[sender.sender_index]
      raise Melos::ProtocolError.new("no external sender #{sender.sender_index} in the external_senders extension") if external_sender.nil?
      external_sender.signature_key
    when Melos::Constants::SenderType::NEW_MEMBER_PROPOSAL
      # the joiner signs its own Add with the key of the KeyPackage's leaf
      content.proposal.add.key_package.leaf_node.signature_key
    else
      # TODO: new-member commits
      raise Melos::UnsupportedError.new('new_member_commit senders are not supported')
    end
  end

  # 6.1, 12.1.8: a message from outside the group is a PublicMessage carrying a proposal of an allowed
  # type (only Add from a new member), and must be authorized by the application
  def validate_non_member_content!(authenticated_content)
    content = authenticated_content.content
    case content.sender.sender_type
    when Melos::Constants::SenderType::EXTERNAL, Melos::Constants::SenderType::NEW_MEMBER_PROPOSAL
      raise Melos::ProtocolError.new('a proposal from outside the group must be a PublicMessage') unless authenticated_content.wire_format == Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE
      raise Melos::ProtocolError.new('a message from outside the group must be a proposal') unless content.content_type == Melos::Constants::ContentType::PROPOSAL
      allowed = content.sender.sender_type == Melos::Constants::SenderType::EXTERNAL ? EXTERNAL_PROPOSAL_TYPES : [Melos::Constants::ProposalType::ADD]
      proposal_type = content.proposal.proposal_type
      raise Melos::ProtocolError.new("proposal type #{proposal_type} cannot be sent from outside the group by this sender") unless allowed.include?(proposal_type)
      raise Melos::ProtocolError.new('external proposal not authorized') unless @external_proposal_validator.call(authenticated_content)
    when Melos::Constants::SenderType::NEW_MEMBER_COMMIT
      raise Melos::ProtocolError.new('a new_member_commit message must be a commit') unless content.content_type == Melos::Constants::ContentType::COMMIT
    else
      raise Melos::ProtocolError.new("unknown sender type #{content.sender.sender_type}")
    end
  end

  # 12.4: the proposals a Commit covers, by value or by reference, as [proposal, sender leaf index] pairs;
  # the sender is nil for a proposal from an external sender or a new member (12.1.8)
  def resolve_proposals(proposal_or_refs, committer)
    proposal_or_refs.map do |proposal_or_ref|
      if proposal_or_ref.proposal
        [proposal_or_ref.proposal, committer]
      else
        authenticated_content = @pending_proposals[proposal_or_ref.reference]
        raise Melos::ProtocolError.new('commit references a proposal we have not received') if authenticated_content.nil?
        sender = authenticated_content.content.sender
        [authenticated_content.content.proposal, sender.sender_type == Melos::Constants::SenderType::MEMBER ? sender.leaf_index : nil]
      end
    end
  end

  # 12.3: apply proposals to tree, in the order GroupContextExtensions, Update, Remove, Add, PreSharedKey,
  # validating each leaf node that goes in (7.3, 10.1) and the resulting membership (12.2).
  #   sending: we are the committer, so lifetimes are checked against the current time (7.3)
  # Returns [extensions, joiners (Joiner for each added member), psk_ids]
  def apply_proposals(tree, proposals, sending:)
    of_type = ->(type) { proposals.select { |proposal, _sender| proposal.proposal_type == type } }
    types = proposals.map { |proposal, _sender| proposal.proposal_type }
    # 12.2, 13.2: a proposal type not supported by every member makes the list invalid; we support only the RFC's own types
    unknown = types - KNOWN_PROPOSAL_TYPES
    raise Melos::UnsupportedError.new("unknown proposal types: #{unknown.map { '0x%04x' % _1 }.join(', ')}") unless unknown.empty?
    unsupported = types & [Melos::Constants::ProposalType::REINIT, Melos::Constants::ProposalType::EXTERNAL_INIT]
    raise Melos::UnsupportedError.new("unsupported proposal types: #{unsupported.map { Melos::Constants::ProposalType::NAMES[_1] }.join(', ')}") unless unsupported.empty?
    extensions = @extensions
    of_type.(Melos::Constants::ProposalType::GROUP_CONTEXT_EXTENSIONS).each do |proposal, _sender|
      Melos::Struct::Extension.check_unique_types!(proposal.group_context_extensions.extensions, 'GroupContextExtensions proposal')
      extensions = proposal.group_context_extensions.extensions
    end
    of_type.(Melos::Constants::ProposalType::UPDATE).each do |proposal, sender|
      validate_leaf_node!(proposal.update.leaf_node, context: :update, leaf_index: sender, tree: tree, extensions: extensions,
                                                     replacing: tree.leaf_node_at(sender), sending: sending)
      tree.update_leaf_node(sender, proposal.update.leaf_node)
    end
    of_type.(Melos::Constants::ProposalType::REMOVE).each do |proposal, _sender|
      # 12.1.3: removed MUST identify a non-blank leaf (this also rejects two Removes of the same leaf, 12.2)
      raise Melos::ProtocolError.new("Remove proposal names a blank leaf (#{proposal.remove.removed})") if tree.leaf_node_at(proposal.remove.removed).nil?
      tree.remove_leaf_node(proposal.remove.removed)
    end
    joiners = of_type.(Melos::Constants::ProposalType::ADD).map do |proposal, _sender|
      key_package = proposal.add.key_package
      # 10.1: the KeyPackage's version and cipher suite MUST match the group's
      raise Melos::ProtocolError.new("Add proposal's KeyPackage has version #{key_package.version}") unless key_package.version == Melos::Constants::Version::MLS10
      raise Melos::ProtocolError.new("Add proposal's KeyPackage is for cipher suite #{key_package.cipher_suite}") unless key_package.cipher_suite == @suite.suite_id
      leaf_index = tree.add_leaf_node(key_package.leaf_node)
      validate_key_package!(key_package, tree: tree, leaf_index: leaf_index, extensions: extensions, sending: sending)
      Joiner.new(leaf_index, key_package)
    end
    psk_ids = of_type.(Melos::Constants::ProposalType::PSK).map { |proposal, _sender| proposal.psk.psk }
    external_senders(extensions) # 12.1.8.1: a malformed external_senders extension is rejected here
    # 12.2, 12.1.7: the members that remain must all be compatible with the new extensions and with each other
    validate_members!(tree, extensions)
    [extensions, joiners, psk_ids]
  end

  # 8.4: the PSK secret for the PreSharedKeyIDs of a commit
  def psk_secret_for(psk_ids)
    psks = psk_ids.map do |psk_id|
      # 12.1.4: psk_nonce MUST be KDF.Nh bytes long
      raise Melos::ProtocolError.new('psk_nonce has the wrong length') unless psk_id.psk_nonce.bytesize == @suite.kdf.n_h
      value =
        case psk_id.psktype
        when Melos::Constants::PSKType::EXTERNAL
          @external_psks.fetch(psk_id.psk_id) { raise Melos::StateError.new('commit references an unknown external PSK') }
        when Melos::Constants::PSKType::RESUMPTION
          # TODO: check psk_group_id and usage
          @resumption_psks.fetch(psk_id.psk_epoch) { raise Melos::StateError.new("no resumption PSK for epoch #{psk_id.psk_epoch}") }
        end
      [psk_id.raw, value]
    end
    Melos::PSK.psk_secret(@suite, psks)
  end

  # 6: FramedContent -> AuthenticatedContent, signed with our key in the current GroupContext
  def frame_and_sign(content_type, content, wire_format:, authenticated_data:)
    framed_content = Melos::Struct::FramedContent.create(
      group_id: @group_id, epoch: @epoch, sender: Melos::Struct::Sender.create_member(@leaf_index),
      authenticated_data: authenticated_data, content_type: content_type, content: content
    )
    authenticated_content = Melos::Struct::AuthenticatedContent.create(wire_format: wire_format, content: framed_content, auth: nil)
    authenticated_content.sign(@suite, @signature_private_key, group_context)
    authenticated_content
  end

  # 6.2, 6.3: AuthenticatedContent -> PublicMessage or PrivateMessage, wrapped in an MLSMessage
  def protect_authenticated_content(authenticated_content, padding_size:)
    case authenticated_content.wire_format
    when Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE
      message = Melos::Struct::PublicMessage.protect(authenticated_content, @suite, @epoch_secrets.membership_key, group_context)
      Melos::Struct::MLSMessage.create(public_message: message)
    when Melos::Constants::WireFormat::MLS_PRIVATE_MESSAGE
      message = Melos::Struct::PrivateMessage.protect(authenticated_content, @suite, @epoch_secrets.secret_tree, @epoch_secrets.sender_data_secret, padding_size)
      Melos::Struct::MLSMessage.create(private_message: message)
    else
      raise ArgumentError.new('wire format must be PublicMessage or PrivateMessage')
    end
  end
end

require_relative 'group/validation'
