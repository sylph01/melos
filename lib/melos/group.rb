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

  attr_reader :suite, :group_id, :epoch, :leaf_index, :ratchet_tree, :private_tree, :extensions,
              :confirmed_transcript_hash, :interim_transcript_hash, :epoch_secrets, :resumption_psks, :external_psks

  # Use .create or .from_welcome rather than calling this directly.
  #   credential_validator: ->(credential, leaf_node) { true/false }, the application's Authentication Service check (5.3.1);
  #                         the default accepts basic credentials only
  #   max_leaf_node_lifetime: longest acceptable Lifetime of a leaf node in seconds (7.2); nil for no limit
  def initialize(suite:, group_id:, epoch:, leaf_index:, signature_private_key:, ratchet_tree:, private_tree:,
                 extensions:, confirmed_transcript_hash:, interim_transcript_hash:, epoch_secrets:, external_psks: {},
                 credential_validator: DEFAULT_CREDENTIAL_VALIDATOR, max_leaf_node_lifetime: DEFAULT_MAX_LEAF_NODE_LIFETIME)
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
    @resumption_psks = { epoch => epoch_secrets.resumption_psk } # epoch -> resumption_psk (8.4)
    @pending_proposals = {} # ProposalRef -> AuthenticatedContent, sent or received in the current epoch (12.4)
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
    raise ArgumentError.new("unsupported MLS version #{mls_message.version}")
  end

  # 11: create a group whose only member is this leaf
  #   external_psks: psk_id -> psk, for external PSKs that commits may reference
  def self.create(suite, group_id, leaf_node, encryption_private_key:, signature_private_key:, extensions: [], external_psks: {}, **options)
    Melos::Struct::Extension.check_unique_types!(extensions, 'GroupContext extensions')
    ratchet_tree = Melos::RatchetTree.new(suite, [Melos::Struct::Node.new_leaf_node(leaf_node)])
    private_tree = Melos::PrivateTree.new
    private_tree[0] = encryption_private_key
    group_context = Melos::Struct::GroupContext.create(
      cipher_suite: suite.suite_id, group_id: group_id, epoch: 0,
      tree_hash: ratchet_tree.root_tree_hash, confirmed_transcript_hash: '', extensions: extensions
    )
    # 8: epoch 0 is derived from a fresh random init_secret, an all-zero commit secret and no PSKs
    epoch_secrets = Melos::EpochSecrets.from_init_secret(suite, SecureRandom.random_bytes(suite.kdf.n_h))
      .next(Melos::Crypto::Util.zero_vector(suite.kdf.n_h), Melos::PSK.psk_secret(suite, []), group_context, n_leaves: 1)
    confirmation_tag = Melos::Crypto.mac(suite, epoch_secrets.confirmation_key, '')
    new(
      suite: suite, group_id: group_id, epoch: 0, leaf_index: 0, signature_private_key: signature_private_key,
      ratchet_tree: ratchet_tree, private_tree: private_tree, extensions: extensions,
      confirmed_transcript_hash: '', interim_transcript_hash: interim_transcript_hash(suite, '', confirmation_tag),
      epoch_secrets: epoch_secrets, external_psks: external_psks, **options
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
    if welcome.is_a?(Melos::Struct::MLSMessage)
      check_message_version!(welcome)
      welcome = welcome.welcome
    end
    raise ArgumentError.new('not a Welcome message') if welcome.nil?
    raise ArgumentError.new('Welcome is for a different cipher suite') unless welcome.cipher_suite == suite.suite_id
    key_package = key_package.key_package if key_package.is_a?(Melos::Struct::MLSMessage)
    # 12.4.3.1: the KeyPackage and the Welcome must be for the same cipher suite
    raise ArgumentError.new('KeyPackage and Welcome are for different cipher suites') unless key_package.cipher_suite == welcome.cipher_suite

    # Identify the entry in welcome.secrets corresponding to our KeyPackage and decrypt it with init_priv
    key_package_ref = key_package.ref(suite)
    encrypted_group_secrets = welcome.secrets.find { _1.new_member == key_package_ref }&.encrypted_group_secrets
    raise ArgumentError.new('Welcome has no entry for this KeyPackage') if encrypted_group_secrets.nil?
    group_secrets = Melos::Struct::GroupSecrets.new(
      Melos::Crypto.decrypt_with_label(
        suite, init_private_key, "Welcome", welcome.encrypted_group_info,
        encrypted_group_secrets.kem_output, encrypted_group_secrets.ciphertext
      )
    )

    # 8.4: the PSKs named in GroupSecrets
    # TODO: resumption PSKs in a Welcome (reinit, branch)
    psks = group_secrets.psks.map do |psk_id|
      raise ArgumentError.new('unsupported PSK type in Welcome') unless psk_id.psktype == Melos::Constants::PSKType::EXTERNAL
      [psk_id.raw, external_psks.fetch(psk_id.psk_id) { raise ArgumentError.new('Welcome references an unknown external PSK') }]
    end
    psk_secret = Melos::PSK.psk_secret(suite, psks)

    # Decrypt the GroupInfo
    welcome_key, welcome_nonce = Melos::EpochSecrets.welcome_key_and_nonce(suite, group_secrets.joiner_secret, psk_secret)
    group_info = Melos::Struct::GroupInfo.new(
      Melos::Crypto.aead_decrypt(suite, welcome_key, welcome_nonce, "", welcome.encrypted_group_info)
    )
    group_context = group_info.group_context
    raise ArgumentError.new("unsupported MLS version #{group_context.version} in GroupContext") unless group_context.version == Melos::Constants::Version::MLS10
    raise ArgumentError.new('GroupInfo is for a different cipher suite') unless group_context.cipher_suite == suite.suite_id
    Melos::Struct::Extension.check_unique_types!(group_context.extensions, 'GroupContext extensions')
    Melos::Struct::Extension.check_unique_types!(group_info.extensions, 'GroupInfo extensions')

    # The ratchet tree: delivered out of band, or in the GroupInfo's ratchet_tree extension
    ratchet_tree_data = ratchet_tree || group_info.extensions.find { _1.extension_type == Melos::Constants::ExtensionType::RATCHET_TREE }&.extension_data
    raise ArgumentError.new('no ratchet tree available') if ratchet_tree_data.nil?
    tree = Melos::RatchetTree.parse(suite, ratchet_tree_data)
    raise ArgumentError.new('tree hash does not match GroupContext') unless tree.root_tree_hash == group_context.tree_hash

    # Verify the GroupInfo signature with the signer's leaf
    signer_leaf_node = tree.leaf_node_at(group_info.signer)
    raise ArgumentError.new('GroupInfo signer is not in the tree') if signer_leaf_node.nil?
    raise ArgumentError.new('GroupInfo signature does not verify') unless group_info.verify(suite, signer_leaf_node.signature_key)

    # Find our own leaf: the one identical to our KeyPackage's LeafNode
    leaf_index = tree.find_leaf_index { _1.raw == key_package.leaf_node.raw }
    raise ArgumentError.new('our KeyPackage is not in the tree') if leaf_index.nil?
    private_tree = Melos::PrivateTree.new
    private_tree[leaf_index * 2] = encryption_private_key
    # 12.4.3.1: a path secret in GroupSecrets is that of the common ancestor of our leaf and the signer's
    if group_secrets.path_secret
      common_ancestor = Melos::Tree.common_ancestor_semantic(leaf_index * 2, group_info.signer * 2, tree.n_leaves)
      private_tree.set_path_secret(tree, common_ancestor, group_secrets.path_secret.path_secret)
    end

    # Enter the epoch's key schedule and check the GroupInfo's confirmation tag against it
    epoch_secrets = Melos::EpochSecrets.from_joiner(suite, group_secrets.joiner_secret, psk_secret, group_context, n_leaves: tree.n_leaves)
    expected_tag = Melos::Crypto.mac(suite, epoch_secrets.confirmation_key, group_context.confirmed_transcript_hash)
    raise ArgumentError.new('GroupInfo confirmation tag does not verify') unless group_info.confirmation_tag == expected_tag

    group = new(
      suite: suite, group_id: group_context.group_id, epoch: group_context.epoch, leaf_index: leaf_index,
      signature_private_key: signature_private_key, ratchet_tree: tree, private_tree: private_tree,
      extensions: group_context.extensions, confirmed_transcript_hash: group_context.confirmed_transcript_hash,
      interim_transcript_hash: interim_transcript_hash(suite, group_context.confirmed_transcript_hash, group_info.confirmation_tag),
      epoch_secrets: epoch_secrets, external_psks: external_psks, **options
    )
    group.send(:validate_joined_state!)
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

  ## Receiving messages (6, 12.4)

  # Unprotect an MLSMessage sent in this group in the current epoch and verify its signature.
  # Returns the Melos::Struct::AuthenticatedContent.
  def unprotect(mls_message)
    self.class.check_message_version!(mls_message)
    authenticated_content =
      case mls_message.wire_format
      when Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE
        mls_message.public_message.unprotect(@suite, @epoch_secrets.membership_key, group_context) or
          raise ArgumentError.new('membership tag does not verify')
      when Melos::Constants::WireFormat::MLS_PRIVATE_MESSAGE
        # TODO: messages from earlier epochs need that epoch's secret tree
        mls_message.private_message.unprotect(@suite, @epoch_secrets.secret_tree, @epoch_secrets.sender_data_secret)
      else
        raise ArgumentError.new('not a PublicMessage or PrivateMessage')
      end
    content = authenticated_content.content
    raise ArgumentError.new('message is for a different group') unless content.group_id == @group_id
    raise ArgumentError.new("message is for epoch #{content.epoch}, current epoch is #{@epoch}") unless content.epoch == @epoch
    raise ArgumentError.new('signature does not verify') unless authenticated_content.verify(@suite, sender_signature_key(content.sender), group_context)
    authenticated_content
  end

  # Unprotect a message and act on it: cache a proposal, apply a commit, hand back application data.
  # Returns the Melos::Struct::AuthenticatedContent in every case.
  def process_message(mls_message)
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
    @ratchet_tree = staged.ratchet_tree
    @private_tree = staged.private_tree
    @extensions = staged.extensions
    @confirmed_transcript_hash = staged.confirmed_transcript_hash
    @interim_transcript_hash = staged.interim_transcript_hash
    @epoch_secrets = staged.epoch_secrets
    @epoch += 1
    @group_context = nil
    @pending_proposals = {}
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
    raise ArgumentError.new('proposals are pending in this epoch; commit them before sending application data') unless @pending_proposals.empty?
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
      raise ArgumentError.new('KeyPackage version differs from its MLSMessage') unless key_package.key_package.version == key_package.version
      key_package = key_package.key_package
    end
    validate_key_package!(key_package, tree: @ratchet_tree, leaf_index: nil, extensions: @extensions, sending: true)
    add = Melos::Struct::Add.create(key_package: key_package)
    create_proposal(Melos::Struct::Proposal.create(proposal_type: Melos::Constants::ProposalType::ADD, add: add), **options)
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

  # 12.4: commit the proposals of this epoch (those sent or received, by reference, plus inline_proposals by value)
  # with a fresh UpdatePath. Returns a CommitResult; call #merge_commit(result.staged) once the Delivery Service
  # has accepted the commit, and send result.welcome to the new members if there are any.
  def create_commit(inline_proposals: [], wire_format: Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE, authenticated_data: '',
                    padding_size: 0, include_ratchet_tree: true)
    ensure_active!
    proposal_or_refs =
      @pending_proposals.keys.map { Melos::Struct::ProposalOrRef.create(type: Melos::Constants::ProposalOrRefType::REFERENCE, proposal: nil, reference: _1) } +
      inline_proposals.map { Melos::Struct::ProposalOrRef.create(type: Melos::Constants::ProposalOrRefType::PROPOSAL, proposal: _1, reference: nil) }
    proposals = resolve_proposals(proposal_or_refs, @leaf_index)
    validate_proposal_list!(proposals, @leaf_index)

    # 12.4.2: the UpdatePath is built on the tree after the proposals, and not encrypted to the leaves being added
    tree = @ratchet_tree.dup
    private_tree = @private_tree.dup
    extensions, joiners, _psk_ids = apply_proposals(tree, proposals, sending: true)
    # TODO: the path may be left out when 12.4 does not require it
    provisional_group_context = Melos::Struct::GroupContext.create(
      cipher_suite: @suite.suite_id, group_id: @group_id, epoch: @epoch + 1,
      tree_hash: '', confirmed_transcript_hash: @confirmed_transcript_hash, extensions: extensions # tree_hash is filled in by create_update_path
    )
    path = tree.create_update_path(private_tree, @leaf_index, @signature_private_key, provisional_group_context, joiners.map { _1.leaf_index * 2 })

    commit = Melos::Struct::Commit.create(proposals: proposal_or_refs, path: path[:update_path])
    authenticated_content = frame_and_sign(Melos::Constants::ContentType::COMMIT, commit, wire_format: wire_format, authenticated_data: authenticated_data)
    staged = stage(authenticated_content, own_path: { private_tree: private_tree, commit_secret: path[:commit_secret], path_secrets: path[:path_secrets] })
    authenticated_content.auth.confirmation_tag = staged.confirmation_tag

    CommitResult.new(
      commit: protect_authenticated_content(authenticated_content, padding_size: padding_size),
      welcome: staged.joiners.empty? ? nil : create_welcome(staged, include_ratchet_tree: include_ratchet_tree),
      staged: staged
    )
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
    raise ArgumentError.new("commit is for epoch #{content.epoch}, current epoch is #{@epoch}") unless content.epoch == @epoch
    # TODO: external and new-member commits
    raise ArgumentError.new('only commits from members are supported') unless content.sender.sender_type == Melos::Constants::SenderType::MEMBER
    committer = content.sender.leaf_index
    raise ArgumentError.new('our own commit must be staged through create_commit') if committer == @leaf_index && own_path.nil?
    commit = content.commit

    proposals = resolve_proposals(commit.proposals, committer)
    validate_proposal_list!(proposals, committer)
    # 12.4: the path is required if the proposal list is empty or contains any of these
    path_required = proposals.empty? || proposals.any? do |proposal, _sender|
      [Melos::Constants::ProposalType::UPDATE, Melos::Constants::ProposalType::REMOVE,
       Melos::Constants::ProposalType::EXTERNAL_INIT, Melos::Constants::ProposalType::GROUP_CONTEXT_EXTENSIONS].include?(proposal.proposal_type)
    end
    raise ArgumentError.new('commit must have a path') if commit.path.nil? && path_required

    tree = @ratchet_tree.dup
    private_tree = own_path ? own_path[:private_tree] : @private_tree.dup
    extensions, joiners, psk_ids = apply_proposals(tree, proposals, sending: !own_path.nil?)

    # 12.4.2: a commit may remove us; we cannot follow it any further, since the path is not encrypted to us.
    # Our leaf index may be non-blank afterwards if an Add in the same commit reused it, so look at the Removes themselves.
    removes_us = proposals.any? { |proposal, _sender| proposal.proposal_type == Melos::Constants::ProposalType::REMOVE && proposal.remove.removed == @leaf_index }
    if removes_us
      return StagedCommit.new(ratchet_tree: tree, extensions: extensions, joiners: joiners, psk_ids: psk_ids, removes_us: true)
    end

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
      raise ArgumentError.new('confirmation tag does not verify')
    end

    StagedCommit.new(
      ratchet_tree: tree, private_tree: private_tree, extensions: extensions,
      confirmed_transcript_hash: confirmed_transcript_hash,
      interim_transcript_hash: self.class.interim_transcript_hash(@suite, confirmed_transcript_hash, confirmation_tag),
      epoch_secrets: epoch_secrets, group_context: new_group_context, confirmation_tag: confirmation_tag,
      joiners: joiners, path_secrets: own_path && own_path[:path_secrets], psk_ids: psk_ids
    )
  end

  def ensure_active!
    raise ArgumentError.new("this member was removed from the group in epoch #{@epoch}") unless @active
  end

  # 6.1: the key that signed a message from this sender
  def sender_signature_key(sender)
    case sender.sender_type
    when Melos::Constants::SenderType::MEMBER
      leaf_node = @ratchet_tree.leaf_node_at(sender.leaf_index)
      raise ArgumentError.new("sender leaf #{sender.leaf_index} is blank") if leaf_node.nil?
      leaf_node.signature_key
    else
      # TODO: external senders (external_senders extension) and new members (KeyPackage in the message)
      raise ArgumentError.new('only messages from members are supported')
    end
  end

  # 12.4: the proposals a Commit covers, by value or by reference, as [proposal, sender leaf index] pairs
  def resolve_proposals(proposal_or_refs, committer)
    proposal_or_refs.map do |proposal_or_ref|
      if proposal_or_ref.proposal
        [proposal_or_ref.proposal, committer]
      else
        authenticated_content = @pending_proposals[proposal_or_ref.reference]
        raise ArgumentError.new('commit references a proposal we have not received') if authenticated_content.nil?
        sender = authenticated_content.content.sender
        raise ArgumentError.new('proposals from external senders are not supported yet') unless sender.sender_type == Melos::Constants::SenderType::MEMBER
        [authenticated_content.content.proposal, sender.leaf_index]
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
    raise ArgumentError.new("unknown proposal types: #{unknown.map { '0x%04x' % _1 }.join(', ')}") unless unknown.empty?
    unsupported = types & [Melos::Constants::ProposalType::REINIT, Melos::Constants::ProposalType::EXTERNAL_INIT]
    raise ArgumentError.new("unsupported proposal types: #{unsupported.map { Melos::Constants::ProposalType::NAMES[_1] }.join(', ')}") unless unsupported.empty?
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
      raise ArgumentError.new("Remove proposal names a blank leaf (#{proposal.remove.removed})") if tree.leaf_node_at(proposal.remove.removed).nil?
      tree.remove_leaf_node(proposal.remove.removed)
    end
    joiners = of_type.(Melos::Constants::ProposalType::ADD).map do |proposal, _sender|
      key_package = proposal.add.key_package
      # 10.1: the KeyPackage's version and cipher suite MUST match the group's
      raise ArgumentError.new("Add proposal's KeyPackage has version #{key_package.version}") unless key_package.version == Melos::Constants::Version::MLS10
      raise ArgumentError.new("Add proposal's KeyPackage is for cipher suite #{key_package.cipher_suite}") unless key_package.cipher_suite == @suite.suite_id
      leaf_index = tree.add_leaf_node(key_package.leaf_node)
      validate_key_package!(key_package, tree: tree, leaf_index: leaf_index, extensions: extensions, sending: sending)
      Joiner.new(leaf_index, key_package)
    end
    psk_ids = of_type.(Melos::Constants::ProposalType::PSK).map { |proposal, _sender| proposal.psk.psk }
    # 12.2, 12.1.7: the members that remain must all be compatible with the new extensions and with each other
    validate_members!(tree, extensions)
    [extensions, joiners, psk_ids]
  end

  # 8.4: the PSK secret for the PreSharedKeyIDs of a commit
  def psk_secret_for(psk_ids)
    psks = psk_ids.map do |psk_id|
      # 12.1.4: psk_nonce MUST be KDF.Nh bytes long
      raise ArgumentError.new('psk_nonce has the wrong length') unless psk_id.psk_nonce.bytesize == @suite.kdf.n_h
      value =
        case psk_id.psktype
        when Melos::Constants::PSKType::EXTERNAL
          @external_psks.fetch(psk_id.psk_id) { raise ArgumentError.new('commit references an unknown external PSK') }
        when Melos::Constants::PSKType::RESUMPTION
          # TODO: check psk_group_id and usage
          @resumption_psks.fetch(psk_id.psk_epoch) { raise ArgumentError.new("no resumption PSK for epoch #{psk_id.psk_epoch}") }
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
