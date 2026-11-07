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
  # 12.4.2: the state of the next epoch, computed from a Commit but not yet in effect.
  # It is produced by #stage_commit and applied by #merge_commit.
  StagedCommit = Struct.new(
    :ratchet_tree, :private_tree, :extensions, :confirmed_transcript_hash, :interim_transcript_hash,
    :epoch_secrets, :group_context, :joiners,
    keyword_init: true
  )

  attr_reader :suite, :group_id, :epoch, :leaf_index, :ratchet_tree, :private_tree, :extensions,
              :confirmed_transcript_hash, :interim_transcript_hash, :epoch_secrets, :resumption_psks, :external_psks

  # Use .create or .from_welcome rather than calling this directly.
  def initialize(suite:, group_id:, epoch:, leaf_index:, signature_private_key:, ratchet_tree:, private_tree:,
                 extensions:, confirmed_transcript_hash:, interim_transcript_hash:, epoch_secrets:, external_psks: {})
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
    @resumption_psks = { epoch => epoch_secrets.resumption_psk } # epoch -> resumption_psk (8.4)
    @pending_proposals = {} # ProposalRef -> AuthenticatedContent received in the current epoch (12.4)
    @group_context = nil
  end

  # 11: create a group whose only member is this leaf
  def self.create(suite, group_id, leaf_node, encryption_private_key:, signature_private_key:, extensions: [])
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
      epoch_secrets: epoch_secrets
    )
  end

  # 12.4.3.1: join a group from a Welcome.
  #   welcome: a Melos::Struct::MLSMessage carrying a Welcome, or the Welcome itself
  #   key_package: the KeyPackage (or MLSMessage carrying it) this member published
  #   init_private_key, encryption_private_key: private keys of the KeyPackage's init_key and leaf encryption_key
  #   external_psks: psk_id -> psk, for any external PSKs the Welcome references
  #   ratchet_tree: serialized tree, if it was delivered outside the Welcome's ratchet_tree extension
  def self.from_welcome(suite, welcome, key_package:, init_private_key:, encryption_private_key:, signature_private_key:,
                        external_psks: {}, ratchet_tree: nil)
    welcome = welcome.welcome if welcome.is_a?(Melos::Struct::MLSMessage)
    raise ArgumentError.new('not a Welcome message') if welcome.nil?
    raise ArgumentError.new('Welcome is for a different cipher suite') unless welcome.cipher_suite == suite.suite_id
    key_package = key_package.key_package if key_package.is_a?(Melos::Struct::MLSMessage)

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
    raise ArgumentError.new('GroupInfo is for a different cipher suite') unless group_context.cipher_suite == suite.suite_id

    # The ratchet tree: delivered out of band, or in the GroupInfo's ratchet_tree extension
    ratchet_tree_data = ratchet_tree || group_info.extensions.find { _1.extension_type == Melos::Constants::ExtensionType::RATCHET_TREE }&.extension_data
    raise ArgumentError.new('no ratchet tree available') if ratchet_tree_data.nil?
    tree = Melos::RatchetTree.parse(suite, ratchet_tree_data)
    raise ArgumentError.new('tree hash does not match GroupContext') unless tree.root_tree_hash == group_context.tree_hash
    # TODO: verify parent hashes and leaf node signatures of the tree (12.4.3.1)

    # Verify the GroupInfo signature with the signer's leaf
    signer_leaf_node = tree.leaf_node_at(group_info.signer)
    raise ArgumentError.new('GroupInfo signer is not in the tree') if signer_leaf_node.nil?
    raise ArgumentError.new('GroupInfo signature does not verify') unless group_info.verify(suite, signer_leaf_node.signature_key)

    # Find our own leaf by the encryption key of our KeyPackage
    leaf_index = tree.find_leaf_index { _1.encryption_key == key_package.leaf_node.encryption_key }
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

    new(
      suite: suite, group_id: group_context.group_id, epoch: group_context.epoch, leaf_index: leaf_index,
      signature_private_key: signature_private_key, ratchet_tree: tree, private_tree: private_tree,
      extensions: group_context.extensions, confirmed_transcript_hash: group_context.confirmed_transcript_hash,
      interim_transcript_hash: interim_transcript_hash(suite, group_context.confirmed_transcript_hash, group_info.confirmation_tag),
      epoch_secrets: epoch_secrets, external_psks: external_psks
    )
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

  # 12.4: remember a proposal received in this epoch so a later Commit can reference it
  def process_proposal(authenticated_content)
    raise ArgumentError.new('not a proposal') unless authenticated_content.content.content_type == Melos::Constants::ContentType::PROPOSAL
    @pending_proposals[Melos::Crypto.make_proposal_ref(@suite, authenticated_content.raw)] = authenticated_content
  end

  def process_commit(authenticated_content)
    merge_commit(stage_commit(authenticated_content))
  end

  # 12.4.2: compute the next epoch's state from a Commit without changing this group yet
  def stage_commit(authenticated_content)
    content = authenticated_content.content
    raise ArgumentError.new('not a commit') unless content.content_type == Melos::Constants::ContentType::COMMIT
    raise ArgumentError.new("commit is for epoch #{content.epoch}, current epoch is #{@epoch}") unless content.epoch == @epoch
    # TODO: external and new-member commits
    raise ArgumentError.new('only commits from members are supported') unless content.sender.sender_type == Melos::Constants::SenderType::MEMBER
    committer = content.sender.leaf_index
    raise ArgumentError.new('cannot stage our own commit this way yet') if committer == @leaf_index # TODO: done in create_commit
    commit = content.commit

    proposals = resolve_proposals(commit, committer)
    # 12.4: the path is required if the proposal list is empty or contains any of these
    path_required = proposals.empty? || proposals.any? do |proposal, _sender|
      [Melos::Constants::ProposalType::UPDATE, Melos::Constants::ProposalType::REMOVE,
       Melos::Constants::ProposalType::EXTERNAL_INIT, Melos::Constants::ProposalType::GROUP_CONTEXT_EXTENSIONS].include?(proposal.proposal_type)
    end
    raise ArgumentError.new('commit must have a path') if commit.path.nil? && path_required

    tree = @ratchet_tree.dup
    private_tree = @private_tree.dup
    extensions, joiners, psk_ids = apply_proposals(tree, proposals)

    if commit.path
      tree.merge_update_path(committer, commit.path)
      # the UpdatePath is encrypted with the provisional GroupContext: new epoch and tree, old transcript hash
      provisional_group_context = Melos::Struct::GroupContext.create(
        cipher_suite: @suite.suite_id, group_id: @group_id, epoch: @epoch + 1,
        tree_hash: tree.root_tree_hash, confirmed_transcript_hash: @confirmed_transcript_hash, extensions: extensions
      )
      path_secret = tree.decrypt_path_secret(private_tree, commit.path, committer, @leaf_index, provisional_group_context, joiners)
      commit_secret = tree.calculate_commit_secret(commit.path, committer, @leaf_index, path_secret)
    else
      commit_secret = Melos::Crypto::Util.zero_vector(@suite.kdf.n_h)
    end

    # 8.2: transcript hashes
    confirmed_transcript_hash = Melos::Crypto.hash(@suite, @interim_transcript_hash + authenticated_content.confirmed_transcript_hash_input.raw)
    new_group_context = Melos::Struct::GroupContext.create(
      cipher_suite: @suite.suite_id, group_id: @group_id, epoch: @epoch + 1,
      tree_hash: tree.root_tree_hash, confirmed_transcript_hash: confirmed_transcript_hash, extensions: extensions
    )

    # 8: the next epoch's key schedule, then check the committer's confirmation tag against it
    epoch_secrets = @epoch_secrets.next(commit_secret, psk_secret_for(psk_ids), new_group_context, n_leaves: tree.n_leaves)
    expected_tag = Melos::Crypto.mac(@suite, epoch_secrets.confirmation_key, confirmed_transcript_hash)
    raise ArgumentError.new('confirmation tag does not verify') unless authenticated_content.auth.confirmation_tag == expected_tag

    StagedCommit.new(
      ratchet_tree: tree, private_tree: private_tree, extensions: extensions,
      confirmed_transcript_hash: confirmed_transcript_hash,
      interim_transcript_hash: self.class.interim_transcript_hash(@suite, confirmed_transcript_hash, authenticated_content.auth.confirmation_tag),
      epoch_secrets: epoch_secrets, group_context: new_group_context, joiners: joiners
    )
  end

  # 12.4.2: make a staged commit the current state; the group moves to the next epoch
  def merge_commit(staged)
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

  ## Sending messages
  # TODO: these predate the staged-commit flow; create_empty_commit uses a placeholder confirmation
  # tag and does not advance the epoch. They are rebuilt on #protect in the next step.

  def create_add_proposal(key_package)
    add = Melos::Struct::Add.allocate
    add.key_package = key_package
    add_proposal = Melos::Struct::Proposal.allocate
    add_proposal.proposal_type = Melos::Constants::ProposalType::ADD
    add_proposal.add = add
    create_protected_public_message(framed_content(Melos::Constants::ContentType::PROPOSAL, add_proposal))
  end

  def create_remove_proposal(target_leaf_index)
    # TODO: check if target leaf index exists
    remove = Melos::Struct::Remove.allocate
    remove.removed = target_leaf_index
    remove_proposal = Melos::Struct::Proposal.allocate
    remove_proposal.proposal_type = Melos::Constants::ProposalType::REMOVE
    remove_proposal.remove = remove
    create_protected_public_message(framed_content(Melos::Constants::ContentType::PROPOSAL, remove_proposal))
  end

  def create_empty_commit
    # empty commit = update path only
    result = @ratchet_tree.create_update_path(@private_tree.dup, @leaf_index, @signature_private_key, @group_id, group_context)
    commit = Melos::Struct::Commit.create(proposals: [], path: result[:update_path])
    create_protected_public_message(framed_content(Melos::Constants::ContentType::COMMIT, commit))
  end

  private

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
  def resolve_proposals(commit, committer)
    commit.proposals.map do |proposal_or_ref|
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

  # 12.3: apply proposals to tree, in the order GroupContextExtensions, Update, Remove, Add, PreSharedKey.
  # Returns [extensions, joiners (leaf indexes of added members), psk_ids]
  def apply_proposals(tree, proposals)
    of_type = ->(type) { proposals.select { |proposal, _sender| proposal.proposal_type == type } }
    unsupported = proposals.map { |proposal, _| proposal.proposal_type } & [Melos::Constants::ProposalType::REINIT, Melos::Constants::ProposalType::EXTERNAL_INIT]
    raise ArgumentError.new("unsupported proposal types: #{unsupported.map { Melos::Constants::ProposalType::NAMES[_1] }.join(', ')}") unless unsupported.empty?
    # TODO: validate each proposal (12.1) and the list as a whole (12.2)

    extensions = @extensions
    of_type.(Melos::Constants::ProposalType::GROUP_CONTEXT_EXTENSIONS).each do |proposal, _sender|
      extensions = proposal.group_context_extensions.extensions
    end
    of_type.(Melos::Constants::ProposalType::UPDATE).each do |proposal, sender|
      tree.update_leaf_node(sender, proposal.update.leaf_node)
    end
    of_type.(Melos::Constants::ProposalType::REMOVE).each do |proposal, _sender|
      tree.remove_leaf_node(proposal.remove.removed) # TODO: if this is our leaf, we have been removed
    end
    joiners = of_type.(Melos::Constants::ProposalType::ADD).map do |proposal, _sender|
      tree.add_leaf_node(proposal.add.key_package.leaf_node)
    end
    psk_ids = of_type.(Melos::Constants::ProposalType::PSK).map { |proposal, _sender| proposal.psk.psk }
    [extensions, joiners, psk_ids]
  end

  # 8.4: the PSK secret for the PreSharedKeyIDs of a commit
  def psk_secret_for(psk_ids)
    psks = psk_ids.map do |psk_id|
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

  def framed_content(content_type, content)
    Melos::Struct::FramedContent.create(
      group_id: @group_id,
      epoch: @epoch,
      sender: Melos::Struct::Sender.create_member(@leaf_index),
      authenticated_data: "authenticated_data", # 6.3.1: it is up to the application to decide what authenticated_data to provide and how much padding to add to a given message (if any)
      content_type: content_type,
      content: content
    )
  end

  def create_protected_public_message(framed_content)
    authenticated_content = Melos::Struct::AuthenticatedContent.create(
      wire_format: Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE,
      content: framed_content,
      auth: nil
    )
    authenticated_content.sign(@suite, @signature_private_key, group_context)
    if framed_content.content_type == Melos::Constants::ContentType::COMMIT
      # TODO: a real confirmation tag needs the next epoch's confirmation key; see stage_commit
      confirmation_tag = Melos::Crypto.derive_secret(@suite, Melos::Crypto::Util.zero_vector(@suite.kdf.n_h), "confirmation_tag")
      authenticated_content.auth.instance_variable_set(:@confirmation_tag, confirmation_tag)
    end
    Melos::Struct::PublicMessage.protect(authenticated_content, @suite, @epoch_secrets.membership_key, group_context)
  end
end
