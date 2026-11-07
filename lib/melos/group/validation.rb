# Validation of the pieces that enter a group: proposal lists (12.2), UpdatePaths (12.4.2),
# KeyPackages (10.1) and LeafNodes (7.3). All methods raise Melos::ProtocolError on failure.
class Melos::Group
  # 7.2: the proposal and extension types every client implements; they are not listed in Capabilities
  DEFAULT_PROPOSAL_TYPES = (0x0001..0x0007).to_a.freeze
  DEFAULT_EXTENSION_TYPES = (0x0001..0x0005).to_a.freeze

  # 7.2: applications MUST define a maximum acceptable leaf node lifetime (seconds) and pass it as
  # max_leaf_node_lifetime. There is no default limit: interop test vectors use the full uint64 range.
  DEFAULT_MAX_LEAF_NODE_LIFETIME = nil

  # 5.3.1: credentials are validated by the application's Authentication Service. Without one,
  # only basic credentials are accepted, since nothing else can be checked here.
  DEFAULT_CREDENTIAL_VALIDATOR = ->(credential, _leaf_node) { credential.credential_type == Melos::Constants::CredentialType::BASIC }

  private

  # 12.2: the rules a regular commit's proposal list must satisfy as a whole; proposals is [proposal, sender] pairs.
  # "The same client" is taken to mean the same signature key, which the RFC leaves to the application.
  def validate_proposal_list!(proposals, committer)
    of_type = ->(type) { proposals.select { |proposal, _sender| proposal.proposal_type == type } }
    updates = of_type.(Melos::Constants::ProposalType::UPDATE)
    removes = of_type.(Melos::Constants::ProposalType::REMOVE)
    adds    = of_type.(Melos::Constants::ProposalType::ADD)
    psks    = of_type.(Melos::Constants::ProposalType::PSK)
    gces    = of_type.(Melos::Constants::ProposalType::GROUP_CONTEXT_EXTENSIONS)

    raise Melos::ProtocolError.new('commit contains an Update from the committer') if updates.any? { |_proposal, sender| sender == committer }
    removed = removes.map { |proposal, _sender| proposal.remove.removed }
    raise Melos::ProtocolError.new('commit removes its own sender') if removed.include?(committer)
    touched = updates.map { |_proposal, sender| sender } + removed
    repeated = touched.tally.select { |_leaf, count| count > 1 }.keys
    raise Melos::ProtocolError.new("more than one Update or Remove for leaf #{repeated.join(', ')}") unless repeated.empty?

    added_keys = adds.map { |proposal, _sender| proposal.add.key_package.leaf_node.signature_key }
    raise Melos::ProtocolError.new('more than one Add for the same client') unless added_keys.uniq.size == added_keys.size
    staying_keys = []
    @ratchet_tree.each_leaf_node { |leaf_node, leaf_index| staying_keys << leaf_node.signature_key unless removed.include?(leaf_index) }
    raise Melos::ProtocolError.new('Add for a client already in the group') unless (added_keys & staying_keys).empty?

    psk_ids = psks.map { |proposal, _sender| proposal.psk.psk.raw }
    raise Melos::ProtocolError.new('more than one PreSharedKey proposal for the same PreSharedKeyID') unless psk_ids.uniq.size == psk_ids.size
    raise Melos::ProtocolError.new('more than one GroupContextExtensions proposal') if gces.size > 1

    reinits = of_type.(Melos::Constants::ProposalType::REINIT)
    raise Melos::ProtocolError.new('a ReInit proposal must be the only proposal of its commit') if reinits.any? && proposals.size > 1
    reinits.each do |proposal, _sender|
      # 12.1.5: a ReInit must not go to a lower version
      raise Melos::ProtocolError.new("ReInit to version #{proposal.reinit.version}, lower than the group's") if proposal.reinit.version < Melos::Constants::Version::MLS10
      Melos::Struct::Extension.check_unique_types!(proposal.reinit.extensions, 'ReInit extensions')
    end
    # ExternalInit must be absent (12.2); apply_proposals rejects it outside an external commit
  end

  # 12.2: an external commit's list is exactly one ExternalInit, at most one Remove, and PreSharedKeys
  def validate_external_proposal_list!(proposals)
    types = proposals.map { |proposal, _sender| proposal.proposal_type }
    raise Melos::ProtocolError.new('an external commit must have exactly one ExternalInit') unless types.count(Melos::Constants::ProposalType::EXTERNAL_INIT) == 1
    raise Melos::ProtocolError.new('an external commit may have at most one Remove') if types.count(Melos::Constants::ProposalType::REMOVE) > 1
    allowed = [Melos::Constants::ProposalType::EXTERNAL_INIT, Melos::Constants::ProposalType::REMOVE, Melos::Constants::ProposalType::PSK]
    others = types - allowed
    raise Melos::ProtocolError.new("an external commit cannot carry #{others.map { Melos::Constants::ProposalType::NAMES[_1] || _1 }.join(', ')} proposals") unless others.empty?
    psk_ids = proposals.filter_map { |proposal, _sender| proposal.psk.psk.raw if proposal.proposal_type == Melos::Constants::ProposalType::PSK }
    raise Melos::ProtocolError.new('more than one PreSharedKey proposal for the same PreSharedKeyID') unless psk_ids.uniq.size == psk_ids.size
  end

  # 12.2: in a resync external commit, the new leaf must be acceptable as an Update of the leaf it removes;
  # here, that the application's member_matcher takes them for the same member
  def validate_resync!(proposals, leaf_node)
    remove = proposals.find { |proposal, _sender| proposal.proposal_type == Melos::Constants::ProposalType::REMOVE }&.first
    return if remove.nil?
    removed_leaf = @ratchet_tree.leaf_node_at(remove.remove.removed)
    return if removed_leaf && @member_matcher.call(removed_leaf, leaf_node)
    raise Melos::ProtocolError.new('an external commit may only remove an earlier appearance of its committer')
  end

  # 11.2, 11.3, 12.4.3.1: a group joined with a reinit or branch resumption PSK (psk_id) is checked against
  # the group it resumes (old_group): epoch 1, the ReInit's parameters or the old group's suite, and the membership
  def validate_resumption!(psk_id, old_group, member_matcher)
    raise Melos::StateError.new('the group this Welcome resumes is not known') if old_group.nil?
    raise Melos::ProtocolError.new("a resumed group must start in epoch 1, not #{@epoch}") unless @epoch == 1
    old_leaves = []
    old_group.ratchet_tree.each_leaf_node { |leaf_node, _index| old_leaves << leaf_node }
    new_leaves = []
    @ratchet_tree.each_leaf_node { |leaf_node, _index| new_leaves << leaf_node }
    case psk_id.usage
    when Melos::Constants::ResumptionPSKUsage::REINIT
      reinit = old_group.pending_reinit
      raise Melos::ProtocolError.new('the resumed group was not reinitialized') if reinit.nil?
      raise Melos::ProtocolError.new('the reinit PSK is not from the epoch the ReInit was committed in') unless psk_id.psk_epoch == old_group.epoch
      raise Melos::ProtocolError.new('group_id differs from the ReInit') unless @group_id == reinit.group_id
      raise Melos::ProtocolError.new('version differs from the ReInit') unless group_context.version == reinit.version
      raise Melos::ProtocolError.new('cipher suite differs from the ReInit') unless @suite.suite_id == reinit.cipher_suite
      raise Melos::ProtocolError.new('extensions differ from the ReInit') unless @extensions.map(&:raw) == reinit.extensions.map(&:raw)
      # every member of the old group is in the new one
      missing = old_leaves.reject { |old| new_leaves.any? { member_matcher.call(old, _1) } }
      raise Melos::ProtocolError.new('a member of the reinitialized group is missing from the new group') unless missing.empty?
    when Melos::Constants::ResumptionPSKUsage::BRANCH
      raise Melos::ProtocolError.new('a branch must keep the cipher suite of its group') unless @suite.suite_id == old_group.suite.suite_id
      # every member of the new group was in the old one
      extra = new_leaves.reject { |new| old_leaves.any? { member_matcher.call(_1, new) } }
      raise Melos::ProtocolError.new('a member of the branch is not in the group it branches from') unless extra.empty?
    end
  end

  # 12.4.2, 7.6, 7.9.2: a received UpdatePath, checked against the tree after the proposals and before the merge.
  #   new_leaf: the committer joined by this commit (12.4.3.2), so its leaf in tree is the path's own and replaces nothing
  def validate_update_path!(tree, update_path, committer, joiners, extensions, new_leaf: false)
    leaf_node = update_path.leaf_node
    validate_leaf_node!(leaf_node, context: :commit, leaf_index: committer, tree: tree, extensions: extensions,
                                   replacing: new_leaf ? nil : tree.leaf_node_at(committer), sending: false)
    # 7.9.2: the parent hash in the new leaf is the one this tree and path imply
    raise Melos::ProtocolError.new('UpdatePath leaf node parent hash does not verify') unless tree.verify_parent_hash_of_path(committer, update_path)
    # 12.4.2, 16.7: the path's public keys are new to the tree and distinct from each other
    path_keys = [leaf_node.encryption_key] + update_path.nodes.map(&:encryption_key)
    raise Melos::ProtocolError.new('UpdatePath public keys are not distinct') unless path_keys.uniq.size == path_keys.size
    # (the committer's own leaf is left out: 7.3 above already requires a new key, and a joiner's leaf is the path's)
    tree_keys = tree.nodes.each_with_index.filter_map { |node, index| node&.public_encryption_key unless index == committer * 2 }
    raise Melos::ProtocolError.new('a public key in the UpdatePath already appears in the tree') unless (path_keys & tree_keys).empty?
    # 7.6: each node carries one ciphertext per member of its copath resolution, the new leaves excluded
    copath_nodes = tree.copath_nodes_of_filtered_direct_path(committer * 2)
    raise Melos::ProtocolError.new('malformed update path') unless copath_nodes.count == update_path.nodes.count
    excluded = joiners.map { _1.leaf_index * 2 }
    update_path.nodes.each_with_index do |node, i|
      expected = (tree.resolution(copath_nodes[i]) - excluded).count
      next if node.encrypted_path_secret.count == expected
      raise Melos::ProtocolError.new("UpdatePath node #{i} has #{node.encrypted_path_secret.count} ciphertexts, expected #{expected}")
    end
  end


  # 10.1: a KeyPackage being added, in the tree it is (or will be) added to.
  #   leaf_index: where it sits in tree, or nil if it is not in tree yet
  def validate_key_package!(key_package, tree:, leaf_index:, extensions:, sending:)
    raise Melos::ProtocolError.new("KeyPackage has version #{key_package.version}") unless key_package.version == Melos::Constants::Version::MLS10
    raise Melos::ProtocolError.new("KeyPackage is for cipher suite #{key_package.cipher_suite}") unless key_package.cipher_suite == @suite.suite_id
    Melos::Struct::Extension.check_unique_types!(key_package.extensions, 'KeyPackage extensions')
    validate_leaf_node!(key_package.leaf_node, context: :key_package, leaf_index: leaf_index, tree: tree, extensions: extensions, sending: sending)
    raise Melos::ProtocolError.new('KeyPackage signature does not verify') unless key_package.verify
    raise Melos::ProtocolError.new('KeyPackage init_key equals its leaf encryption_key') if key_package.init_key == key_package.leaf_node.encryption_key
    # 10: extensions of the KeyPackage itself must also be in the leaf's capabilities
    unsupported = key_package.extensions.map(&:extension_type) - DEFAULT_EXTENSION_TYPES - key_package.leaf_node.capabilities.export.extensions
    raise Melos::ProtocolError.new("KeyPackage extensions not in its capabilities: #{unsupported.map { '0x%04x' % _1 }.join(', ')}") unless unsupported.empty?
  end

  # 7.3: a LeafNode in one of its contexts.
  #   context: :key_package (in a KeyPackage), :update (an Update proposal), :commit (the leaf of an UpdatePath),
  #            or :tree (a leaf already in the tree, e.g. when joining; its source is taken as given)
  #   leaf_index: the leaf's index in tree (needed to verify update/commit signatures); nil if not in tree yet
  #   tree, extensions: the ratchet tree and GroupContext extensions the leaf must be compatible with
  #   replacing: for :update and :commit, the leaf node being replaced
  #   sending: the leaf is in a message we are about to send, so its lifetime is checked against the current time
  def validate_leaf_node!(leaf_node, context:, leaf_index:, tree:, extensions:, replacing: nil, sending: false)
    expected_source = { key_package: Melos::Constants::LeafNodeSource::KEY_PACKAGE, update: Melos::Constants::LeafNodeSource::UPDATE,
                        commit: Melos::Constants::LeafNodeSource::COMMIT }[context]
    if expected_source && leaf_node.leaf_node_source != expected_source
      raise Melos::ProtocolError.new("leaf node source is #{leaf_node.leaf_node_source}, expected #{expected_source} for #{context}")
    end

    # 5.3.1: the credential, by the application
    raise Melos::ProtocolError.new('leaf node credential rejected') unless @credential_validator.call(leaf_node.credential, leaf_node)

    # the signature; update and commit leaves are bound to this group and leaf index
    verified = if leaf_node.leaf_node_source == Melos::Constants::LeafNodeSource::KEY_PACKAGE
                 leaf_node.verify(@suite, nil, nil)
               else
                 raise ArgumentError.new('leaf index needed to verify this leaf node') if leaf_index.nil?
                 leaf_node.verify(@suite, @group_id, leaf_index)
               end
    raise Melos::ProtocolError.new('leaf node signature does not verify') unless verified

    # 7.3, 11: compatible with the group's version, cipher suite, extensions and required capabilities
    capabilities = leaf_node.capabilities.export
    raise Melos::ProtocolError.new('leaf node does not support MLS 1.0') unless capabilities.versions.include?(Melos::Constants::Version::MLS10)
    raise Melos::ProtocolError.new("leaf node does not support cipher suite #{@suite.suite_id}") unless capabilities.cipher_suites.include?(@suite.suite_id)
    others = []
    tree.each_leaf_node { |other, index| others << other unless index == leaf_index }
    validate_capabilities!(leaf_node, capabilities, extensions, others.map { _1.credential.credential_type })
    # 7.3, 13.3: the other members support this leaf's credential type
    others.each do |other|
      next if other.capabilities.export.credentials.include?(leaf_node.credential.credential_type)
      raise Melos::ProtocolError.new('a current member does not support this leaf node\'s credential type')
    end

    # 7.2, 7.3: lifetime, for leaves that came from a KeyPackage
    if leaf_node.leaf_node_source == Melos::Constants::LeafNodeSource::KEY_PACKAGE
      lifetime = leaf_node.lifetime
      if @max_leaf_node_lifetime && lifetime.not_after - lifetime.not_before > @max_leaf_node_lifetime
        raise Melos::ProtocolError.new('leaf node lifetime is longer than allowed')
      end
      if sending
        now = Time.now.to_i
        raise Melos::ProtocolError.new('leaf node lifetime does not cover the current time') unless lifetime.not_before <= now && now <= lifetime.not_after
      end
    end

    Melos::Struct::Extension.check_unique_types!(leaf_node.extensions, 'leaf node extensions')

    # 7.3, 12.4.2: a replacement leaf brings a new encryption key
    if replacing && leaf_node.encryption_key == replacing.encryption_key
      raise Melos::ProtocolError.new('replacement leaf node reuses the encryption key of the leaf it replaces')
    end
    # 7.3, 16.7: keys are unique among members
    others.each do |other|
      raise Melos::ProtocolError.new('leaf node signature key is already used by another member') if other.signature_key == leaf_node.signature_key
      raise Melos::ProtocolError.new('leaf node encryption key is already used by another member') if other.encryption_key == leaf_node.encryption_key
    end
  end

  # 7.2, 7.3, 11.1, 13.4: a leaf's capabilities cover its own extensions and credential type, the group's
  # non-default extensions, the required_capabilities extension if any, and the credential types in use
  def validate_capabilities!(leaf_node, capabilities, extensions, credential_types_in_use)
    own_extension_types = leaf_node.extensions.map(&:extension_type) - DEFAULT_EXTENSION_TYPES
    missing = own_extension_types - capabilities.extensions
    raise Melos::ProtocolError.new("leaf node extensions not in its capabilities: #{missing.map { '0x%04x' % _1 }.join(', ')}") unless missing.empty?
    raise Melos::ProtocolError.new('leaf node credential type not in its capabilities') unless capabilities.credentials.include?(leaf_node.credential.credential_type)

    group_extension_types = extensions.map(&:extension_type) - DEFAULT_EXTENSION_TYPES
    missing = group_extension_types - capabilities.extensions
    raise Melos::ProtocolError.new("leaf node does not support GroupContext extensions #{missing.map { '0x%04x' % _1 }.join(', ')}") unless missing.empty?

    if (required = required_capabilities(extensions))
      missing = (required.extension_types - DEFAULT_EXTENSION_TYPES) - capabilities.extensions
      raise Melos::ProtocolError.new("leaf node lacks required extensions #{missing.map { '0x%04x' % _1 }.join(', ')}") unless missing.empty?
      missing = (required.proposal_types - DEFAULT_PROPOSAL_TYPES) - capabilities.proposals
      raise Melos::ProtocolError.new("leaf node lacks required proposal types #{missing.map { '0x%04x' % _1 }.join(', ')}") unless missing.empty?
      missing = required.credential_types - capabilities.credentials
      raise Melos::ProtocolError.new("leaf node lacks required credential types #{missing.join(', ')}") unless missing.empty?
    end

    missing = credential_types_in_use.uniq - capabilities.credentials
    raise Melos::ProtocolError.new("leaf node does not support credential types in use: #{missing.join(', ')}") unless missing.empty?
  end

  # 12.2, 12.1.7: after a proposal list is applied, every remaining member is compatible with the (possibly
  # new) extensions and with every other member, and keys are unique. Signatures were checked when each leaf
  # entered the tree, so they are not verified again here.
  def validate_members!(tree, extensions)
    leaves = []
    tree.each_leaf_node { |leaf_node, _index| leaves << leaf_node }
    signature_keys = leaves.map(&:signature_key)
    raise Melos::ProtocolError.new('two members share a signature key') unless signature_keys.uniq.size == signature_keys.size
    encryption_keys = leaves.map(&:encryption_key)
    raise Melos::ProtocolError.new('two members share an encryption key') unless encryption_keys.uniq.size == encryption_keys.size
    credential_types = leaves.map { _1.credential.credential_type }
    leaves.each do |leaf_node|
      validate_capabilities!(leaf_node, leaf_node.capabilities.export, extensions, credential_types)
    end
  end

  # 5.3.1, 12.1.8.1: an external_senders extension parses, and each sender's credential is validated by the
  # application's Authentication Service (the credential_validator gets the ExternalSender as the holder)
  def validate_external_senders!(extensions)
    external_senders(extensions).each do |external_sender|
      next if @credential_validator.call(external_sender.credential, external_sender)
      raise Melos::ProtocolError.new('external sender credential rejected')
    end
  end

  # 12.4.3.1: what a new member checks about the state it was welcomed into, once it is assembled
  def validate_joined_state!
    validate_tree!(@ratchet_tree, @extensions)
    validate_external_senders!(@extensions)
    # the private keys derived from the Welcome's path secret must be the ones for the public keys in the tree
    raise Melos::ProtocolError.new('derived private keys do not match the ratchet tree') unless @private_tree.consistent?(@ratchet_tree)
  end

  # 12.4.3.1, 7.9.2, 7.3: the integrity of a ratchet tree received from someone else.
  # Also what makes 13.4 hold for us: validate_leaf_node! on our own leaf checks that we support every GroupContext extension.
  def validate_tree!(tree, extensions)
    raise Melos::ProtocolError.new('ratchet tree has a parent node that is not parent-hash valid') unless tree.parent_hash_valid?
    tree.each_leaf_node do |leaf_node, leaf_index|
      validate_leaf_node!(leaf_node, context: :tree, leaf_index: leaf_index, tree: tree, extensions: extensions)
    end

    encryption_keys = []
    tree.each_leaf_node { |leaf_node, _index| encryption_keys << leaf_node.encryption_key }
    tree.nodes.each_with_index do |node, node_index|
      next if node.nil? || node.parent_node.nil?
      parent_node = node.parent_node
      encryption_keys << parent_node.encryption_key
      parent_node.unmerged_leaves.each do |leaf_index|
        raise Melos::ProtocolError.new("unmerged leaf #{leaf_index} is blank") if tree.leaf_node_at(leaf_index).nil?
        direct_path = Melos::Tree.direct_path(leaf_index * 2, tree.n_leaves)
        raise Melos::ProtocolError.new("unmerged leaf #{leaf_index} is not under node #{node_index}") unless direct_path.include?(node_index)
        # every non-blank node between the leaf and this node lists the leaf as unmerged too
        direct_path.take_while { _1 != node_index }.each do |between|
          next if tree[between].nil?
          next if tree[between].parent_node.unmerged_leaves.include?(leaf_index)
          raise Melos::ProtocolError.new("unmerged leaf #{leaf_index} of node #{node_index} is merged at node #{between} below it")
        end
      end
    end
    # 12.4.3.1, 16.7: no encryption key appears in two nodes
    raise Melos::ProtocolError.new('an encryption key appears in more than one node of the ratchet tree') unless encryption_keys.uniq.size == encryption_keys.size
  end

  # 11.1: the required_capabilities extension of a GroupContext, decoded, or nil.
  # Returns an object with extension_types, proposal_types and credential_types as integer arrays.
  def required_capabilities(extensions)
    extension = extensions.find { _1.extension_type == Melos::Constants::ExtensionType::REQUIRED_CAPABILITIES }
    return nil if extension.nil?
    struct = Melos::Struct::RequiredCapabilities.new(extension.extension_data)
    Struct.new(:extension_types, :proposal_types, :credential_types).new(
      struct.extension_types.unpack('S>*'), struct.proposal_types.unpack('S>*'), struct.credential_types.unpack('S>*')
    )
  end
end
