require 'securerandom'
require_relative 'crypto'
require_relative 'key_package_bundle'
require_relative 'group'
require_relative 'external_sender'
require_relative 'struct/structs'

# A client (RFC 9420 Section 5.3): a long-lived identity, i.e. a signature key pair and a
# credential, plus what a client keeps across groups: the external PSKs it knows (8.4) and the
# KeyPackages it has published and may still be welcomed into a group with (10), and the
# resumption PSKs of groups it has replaced (8.6), for groups that resume them.
class Melos::Client
  attr_reader :cipher_suite, :credential, :external_psks, :key_packages, :groups

  #   identity: for a basic credential
  #   credential: any other credential (Melos::Credential::X509.create_credential, say); its key is then
  #               signature_private_key, the private key of the certified public key, as MLS serializes it
  #   credential_types: the credential types this client's leaves claim to support (13.3), by default basic
  #                     and its own; members of a group must all support every type in use
  def initialize(cipher_suite_id, identity: '', credential: nil, signature_private_key: nil, credential_types: nil)
    @cipher_suite = Melos::Crypto::CipherSuite.new(cipher_suite_id)
    @signature_key_pair = signature_private_key ? @cipher_suite.pkey.deserialize_private_signature_key(signature_private_key) : Melos::Crypto.generate_signature_key_pair(@cipher_suite)
    @credential = credential || Melos::Struct::Credential.create_basic_credential(identity)
    @credential_types = credential_types || ([Melos::Constants::CredentialType::BASIC] | [@credential.credential_type])
    @external_psks = {} # psk_id -> psk; shared by reference with the groups this client is in
    @key_packages = {}  # KeyPackageRef -> Melos::KeyPackageBundle, until used to join a group
    @groups = {}        # group_id -> Melos::Group this client created or joined
    @resumption_psks = {} # [group_id, epoch] -> resumption_psk, of groups no longer in @groups (8.6)
  end

  # 7.2: the Capabilities this client's leaves carry unless told otherwise
  def default_capabilities
    Melos::Struct::Capabilities.import(Melos::Capabilities.new(credentials: @credential_types))
  end

  # 8.6: the resumption PSK of a group this client is or was in, or nil
  def resumption_psk(group_id, epoch)
    @groups[group_id]&.resumption_psks&.[](epoch) || @resumption_psks[[group_id, epoch]]
  end

  def signature_private_key
    Melos::Crypto.serialize_private_key(@cipher_suite, @signature_key_pair)
  end

  def signature_public_key
    Melos::Crypto.serialize_public_key(@cipher_suite, @signature_key_pair)
  end

  # 8.4: an external PSK that commits in this client's groups may reference
  def add_external_psk(psk_id, psk)
    @external_psks[psk_id] = psk
  end

  # 10: publish a KeyPackage. The bundle is kept so that a Welcome addressed to it can be processed.
  def create_key_package(capabilities: nil, lifetime: nil, extensions: [])
    bundle = Melos::KeyPackageBundle.generate(
      @cipher_suite, signature_private_key: signature_private_key, signature_public_key: signature_public_key,
      credential: @credential, capabilities: capabilities || default_capabilities, lifetime: lifetime, extensions: extensions
    )
    @key_packages[bundle.ref] = bundle
    bundle
  end

  # 12.1.8: ask to join a group by proposing our own Add, as a new_member_proposal signed with the
  # KeyPackage's key. A member who commits it sends a Welcome addressed to that KeyPackage, which
  # #join_group then accepts. group_id and epoch are the group's current ones (from a GroupInfo, say).
  # Returns [MLSMessage, KeyPackageBundle].
  def create_new_member_proposal(group_id:, epoch:, authenticated_data: '', **key_package_options)
    bundle = create_key_package(**key_package_options)
    add = Melos::Struct::Proposal.create(proposal_type: Melos::Constants::ProposalType::ADD, add: Melos::Struct::Add.create(key_package: bundle.key_package))
    sender = Melos::Struct::Sender.create_new_member(Melos::Constants::SenderType::NEW_MEMBER_PROPOSAL)
    message = Melos::ExternalSender.sign_proposal(@cipher_suite, signature_private_key, add, sender,
                                                  group_id: group_id, epoch: epoch, authenticated_data: authenticated_data)
    [message, bundle]
  end

  # 11: create a group with this client as its only member.
  # options are passed to Melos::Group (credential_validator:, max_leaf_node_lifetime:, ...)
  def create_group(group_id, extensions: [], **options)
    bundle = Melos::KeyPackageBundle.generate(
      @cipher_suite, signature_private_key: signature_private_key, signature_public_key: signature_public_key, credential: @credential,
      capabilities: default_capabilities
    )
    ensure_group_id_free!(group_id)
    store_group(Melos::Group.create(
      @cipher_suite, group_id, bundle.key_package.leaf_node,
      encryption_private_key: bundle.encryption_private_key, signature_private_key: signature_private_key,
      extensions: extensions, external_psks: @external_psks, resumption_psk_lookup: method(:resumption_psk), **options
    ))
  end

  # 11.2: create the group that replaces old_group after a ReInit was committed in it, with the ReInit's
  # group_id, cipher suite (this client's) and extensions, and with the same members, given as fresh
  # KeyPackages of every other member. Returns [new group, Welcome]; the new group is already in epoch 1.
  #   member_matcher: ->(old_leaf, new_leaf) { true/false }, whether two leaves are the same member
  def reinit_group(old_group, key_packages, member_matcher: Melos::Group::DEFAULT_MEMBER_MATCHER, **options)
    reinit = old_group.pending_reinit
    raise Melos::StateError.new('no ReInit has been committed in this group') if reinit.nil?
    raise ArgumentError.new("the ReInit is for cipher suite #{reinit.cipher_suite}; use a client of that suite") unless reinit.cipher_suite == @cipher_suite.suite_id
    raise Melos::UnsupportedError.new("unsupported MLS version #{reinit.version}") unless reinit.version == Melos::Constants::Version::MLS10
    new_leaves = key_packages.map { leaf_of(_1) } + [own_leaf]
    old_group.ratchet_tree.each_leaf_node do |old_leaf, _index|
      next if new_leaves.any? { member_matcher.call(old_leaf, _1) }
      raise ArgumentError.new('every member of the old group needs a KeyPackage in the new one')
    end
    resume(old_group, key_packages, Melos::Constants::ResumptionPSKUsage::REINIT, reinit.group_id, reinit.extensions, options)
  end

  # 11.3: branch a subgroup of old_group's members, given as fresh KeyPackages, with a new group_id and
  # the same cipher suite. Returns [new group, Welcome]; the new group is already in epoch 1.
  def branch_group(old_group, key_packages, group_id:, extensions: old_group.extensions, member_matcher: Melos::Group::DEFAULT_MEMBER_MATCHER, **options)
    raise ArgumentError.new('a branch keeps the cipher suite of its group') unless old_group.suite.suite_id == @cipher_suite.suite_id
    old_leaves = []
    old_group.ratchet_tree.each_leaf_node { |leaf_node, _index| old_leaves << leaf_node }
    (key_packages.map { leaf_of(_1) } + [own_leaf]).each do |new_leaf|
      next if old_leaves.any? { member_matcher.call(_1, new_leaf) }
      raise ArgumentError.new('every member of a branch must be a member of the group it branches from')
    end
    resume(old_group, key_packages, Melos::Constants::ResumptionPSKUsage::BRANCH, group_id, extensions, options)
  end

  # 12.4.3.2: join a group by external commit, from a GroupInfo with an external_pub extension (see
  # Melos::Group#group_info). The new group is merged and stored right away; send the commit, and if the
  # Delivery Service rejects it, drop the group (groups.delete(group.group_id)) and try again with a fresh GroupInfo.
  #   remove: the leaf index of this client's earlier appearance in the group, to replace it (a "resync")
  #   psk_ids: external PSKs (added with #add_external_psk) to inject
  # Returns [group, commit MLSMessage].
  def join_by_external_commit(group_info, ratchet_tree: nil, remove: nil, psk_ids: [], authenticated_data: '', **options)
    bundle = Melos::KeyPackageBundle.generate(
      @cipher_suite, signature_private_key: signature_private_key, signature_public_key: signature_public_key, credential: @credential,
      capabilities: default_capabilities
    )
    group, result = Melos::Group.join_by_external_commit(
      @cipher_suite, group_info, signature_private_key: signature_private_key, leaf_node: bundle.key_package.leaf_node,
      ratchet_tree: ratchet_tree, remove: remove, psk_ids: psk_ids, external_psks: @external_psks, authenticated_data: authenticated_data,
      resumption_psk_lookup: method(:resumption_psk), **options
    )
    # a resync replaces this client's own earlier state of the group, which may still be here
    ensure_group_id_free!(group.group_id) unless remove
    group.merge_commit(result.staged)
    store_group(group)
    [group, result.commit]
  end

  # 12.4.3.1: join the group a Welcome adds us to, using whichever of our KeyPackages it is addressed to.
  # That KeyPackage is then forgotten: its init key is single-use.
  #   resumed_groups: groups held elsewhere (by a client of another cipher suite, say) that a reinit or
  #                   branch Welcome may resume; this client's own groups are always looked in
  #   member_matcher: as for #reinit_group, for the checks of 11.2 and 11.3
  def join_group(welcome, ratchet_tree: nil, resumed_groups: [], member_matcher: Melos::Group::DEFAULT_MEMBER_MATCHER, **options)
    welcome_struct = welcome.is_a?(Melos::Struct::MLSMessage) ? welcome.welcome : welcome
    raise ArgumentError.new('not a Welcome message') if welcome_struct.nil?
    bundle = welcome_struct.secrets.map(&:new_member).filter_map { @key_packages[_1] }.first
    raise Melos::ProtocolError.new('Welcome is not addressed to any KeyPackage of this client') if bundle.nil?
    group = Melos::Group.from_welcome(
      @cipher_suite, welcome,
      key_package: bundle.key_package, init_private_key: bundle.init_private_key,
      encryption_private_key: bundle.encryption_private_key, signature_private_key: signature_private_key,
      external_psks: @external_psks, ratchet_tree: ratchet_tree,
      resumption_psk_lookup: ->(group_id, epoch) { resumed_groups.find { _1.group_id == group_id }&.resumption_psks&.[](epoch) || resumption_psk(group_id, epoch) },
      resumed_group_lookup: ->(group_id) { resumed_groups.find { _1.group_id == group_id } || @groups[group_id] },
      member_matcher: member_matcher, **options
    )
    ensure_group_id_free!(group.group_id)
    @key_packages.delete(bundle.ref)
    store_group(group)
  end

  # version of the Hash produced by #to_h
  STATE_FORMAT = 1

  # The client's whole state, its groups included, in the form Melos::Group#to_h describes.
  # Private keys are in it: store it encrypted.
  def to_h
    {
      format: STATE_FORMAT,
      cipher_suite: @cipher_suite.suite_id,
      signature_private_key: signature_private_key,
      credential: @credential.raw, credential_types: @credential_types,
      external_psks: @external_psks.to_a,
      key_packages: @key_packages.map { |ref, bundle| [ref, bundle.to_h] },
      groups: @groups.map { |group_id, group| [group_id, group.to_h(include_external_psks: false)] },
      resumption_psks: @resumption_psks.map { |(group_id, epoch), psk| [group_id, epoch, psk] }
    }
  end

  # A client from #to_h. group_options (credential_validator:, external_proposal_validator:) go to every group.
  def self.from_h(hash, **group_options)
    raise ArgumentError.new("unknown client state format #{hash[:format]}") unless hash[:format] == STATE_FORMAT
    client = allocate
    client.send(:restore_state, hash, group_options)
    client
  end

  private

  def restore_state(hash, group_options)
    @cipher_suite = Melos::Crypto::CipherSuite.new(hash[:cipher_suite])
    @signature_key_pair = @cipher_suite.pkey.deserialize_private_signature_key(hash[:signature_private_key])
    @credential = Melos::Struct::Credential.new(hash[:credential])
    @credential_types = hash[:credential_types] || [Melos::Constants::CredentialType::BASIC]
    @external_psks = hash[:external_psks].to_h
    @key_packages = hash[:key_packages].to_h { |ref, bundle| [ref, Melos::KeyPackageBundle.from_h(@cipher_suite, bundle)] }
    @groups = hash[:groups].to_h do |group_id, group|
      [group_id, Melos::Group.from_h(group, external_psks: @external_psks, resumption_psk_lookup: method(:resumption_psk), **group_options)]
    end
    @resumption_psks = (hash[:resumption_psks] || []).to_h { |group_id, epoch, psk| [[group_id, epoch], psk] }
  end

  # a group goes into @groups; one it replaces (removed or reinitialized, see #ensure_group_id_free!)
  # leaves its resumption PSKs behind for groups that resume it (8.6)
  def store_group(group)
    if (replaced = @groups[group.group_id])
      replaced.resumption_psks.each { |epoch, psk| @resumption_psks[[group.group_id, epoch]] = psk }
    end
    @groups[group.group_id] = group
  end

  # the options of #reinit_group and #branch_group that go to the new group's first commit rather than to the group
  RESUMPTION_COMMIT_OPTIONS = %i[wire_format include_ratchet_tree path].freeze

  # 11.2, 11.3: a new group of this client resuming old_group: created in epoch 0, then a first commit adding
  # key_packages with the resumption PSK of old_group's current epoch, merged at once
  def resume(old_group, key_packages, usage, group_id, extensions, options)
    psk_id = Melos::Struct::PreSharedKeyID.create_resumption(
      usage: usage, psk_group_id: old_group.group_id, psk_epoch: old_group.epoch, psk_nonce: SecureRandom.random_bytes(@cipher_suite.kdf.n_h)
    )
    psk = old_group.resumption_psks.fetch(old_group.epoch)
    commit_options = options.slice(*RESUMPTION_COMMIT_OPTIONS)
    group = create_group(group_id, extensions: extensions, **options.except(*RESUMPTION_COMMIT_OPTIONS))
    result = group.send(:create_resumption_commit, key_packages, psk_id, psk, **commit_options)
    group.merge_commit(result.staged)
    [group, result.welcome]
  end

  def leaf_of(key_package)
    (key_package.is_a?(Melos::Struct::MLSMessage) ? key_package.key_package : key_package).leaf_node
  end

  # a leaf standing for this client, for the membership checks of #reinit_group and #branch_group
  def own_leaf
    Melos::Struct::LeafNode.create(
      encryption_key: '', signature_key: signature_public_key, credential: @credential, capabilities: nil,
      leaf_node_source: nil, lifetime: nil, parent_hash: nil, extensions: [], signature: nil
    )
  end

  # 12.4.3: a group_id MUST be unique among the groups this client is participating in;
  # a group this client has been removed from no longer counts
  def ensure_group_id_free!(group_id)
    existing = @groups[group_id]
    return if existing.nil? || !existing.active?
    raise Melos::StateError.new('this client is already in a group with this group_id')
  end
end
