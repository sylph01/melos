require 'minitest'
require 'melos'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

# Error cases: inputs that RFC 9420 says MUST be rejected. See docs/validation.md.

def wire(message)
  Melos::Struct::MLSMessage.new(message.raw)
end

# a two-member group: returns [alice_group, bob_group, alice, bob]
def two_member_group(suite_id)
  alice = Melos::Client.new(suite_id, identity: 'alice')
  bob = Melos::Client.new(suite_id, identity: 'bob')
  alice_group = alice.create_group("validation-#{suite_id}")
  alice_group.create_add_proposal(wire(bob.create_key_package.message))
  result = alice_group.create_commit
  bob_group = bob.join_group(wire(result.welcome))
  alice_group.merge_commit(result.staged)
  [alice_group, bob_group, alice, bob]
end

suite_id = 1
suite = Melos::Crypto::CipherSuite.new(suite_id)
C = Melos::Constants

## 2.1.2 variable-length vectors
assert_equal "hello", Melos::Vec.parse_stream(StringIO.new("\x05hello"))
assert_raises(Melos::ProtocolError) { Melos::Vec.parse_stream(StringIO.new("\x40\x05hello")) } # length 5 in a 2-byte header
assert_raises(Melos::ProtocolError) { Melos::Vec.parse_stream(StringIO.new("\x05hel")) }       # shorter than its length
assert_raises(Melos::ProtocolError) { Melos::Vec.parse_stream(StringIO.new("\x40")) }          # header cut short
assert_raises(Melos::ProtocolError) { Melos::Vec.parse_stream(StringIO.new("")) }
assert_raises(Melos::ProtocolError) { Melos::Vec.parse_stream(StringIO.new("\xC0\x00\x00\x00")) } # prefix 3
puts "[pass] non-minimal, truncated and invalid vector headers are rejected"

## 7.2 default capabilities list no default types
assert_empty Melos::Capabilities.new.proposals
assert_empty Melos::Capabilities.new.extensions
puts "[pass] default Capabilities list no default proposal or extension types"

alice_group, bob_group, alice, bob = two_member_group(suite_id)

## 6 / 10 version fields
message = alice_group.create_application_message("hi")
tampered = message.raw.dup
tampered[0, 2] = "\x00\x02"
assert_raises(Melos::ProtocolError) { bob_group.process_message(Melos::Struct::MLSMessage.new(tampered)) }
carol = Melos::Client.new(suite_id, identity: 'carol')
key_package_bytes = carol.create_key_package.message.raw.dup
key_package_bytes[0, 2] = "\x00\x02"
assert_raises(Melos::ProtocolError) { alice_group.create_add_proposal(Melos::Struct::MLSMessage.new(key_package_bytes)) }
puts "[pass] messages and KeyPackages with a version other than mls10 are rejected"

## 6.3.1 padding must be zero: make the sender pad with 0x01 bytes
util = Melos::Crypto::Util
util.singleton_class.alias_method(:zero_vector_for_real, :zero_vector)
util.define_singleton_method(:zero_vector) { |length| "\x01" * length }
begin
  bad_padding = alice_group.create_application_message("padded", padding_size: 8)
ensure
  util.singleton_class.alias_method(:zero_vector, :zero_vector_for_real)
end
assert_raises(Melos::ProtocolError) { bob_group.process_message(wire(bad_padding)) }
puts "[pass] a PrivateMessage with non-zero padding is rejected"

## 13.4 duplicate extensions
extension = Melos::Struct::Extension.create(extension_type: 0xF000, extension_data: "")
assert_raises(Melos::ProtocolError) { alice.create_group("dup", extensions: [extension, extension]) }
gce = Melos::Struct::GroupContextExtensions.create(extensions: [extension, extension])
proposal = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::GROUP_CONTEXT_EXTENSIONS, group_context_extensions: gce)
assert_raises(Melos::ProtocolError) { alice_group.create_commit(inline_proposals: [proposal]) }
puts "[pass] extension lists with a repeated type are rejected"

## 12.1.3 Remove of a blank leaf
proposal = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::REMOVE, remove: Melos::Struct::Remove.create(removed: 1))
proposal_blank = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::REMOVE, remove: Melos::Struct::Remove.create(removed: 5))
assert_raises(Melos::ProtocolError) { alice_group.create_commit(inline_proposals: [proposal_blank]) }
assert_raises(Melos::ProtocolError) { alice_group.create_commit(inline_proposals: [proposal, proposal]) } # the second one hits a blank leaf
puts "[pass] a Remove of a blank leaf, or the same leaf twice, is rejected"

## 12.2 a commit must not remove its own sender
self_remove = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::REMOVE, remove: Melos::Struct::Remove.create(removed: 0))
assert_raises(Melos::ProtocolError) { alice_group.create_commit(inline_proposals: [self_remove]) }
puts "[pass] a commit removing its own sender is rejected"

## 12.1.4 psk_nonce length
alice.add_external_psk("k", "secret")
bob.add_external_psk("k", "secret")
short_nonce = Melos::Struct::PreSharedKey.create(psk: Melos::Struct::PreSharedKeyID.create_external(psk_id: "k", psk_nonce: "abc"))
proposal = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::PSK, psk: short_nonce)
assert_raises(Melos::ProtocolError) { alice_group.create_commit(inline_proposals: [proposal]) }
puts "[pass] a PreSharedKey proposal with a nonce of the wrong length is rejected"

## 12.2 / 13.2 unknown proposal type
proposal = Melos::Struct::Proposal.create(proposal_type: 0x0042)
assert_raises(Melos::UnsupportedError) { alice_group.create_commit(inline_proposals: [proposal]) } # a type we do not implement
puts "[pass] a proposal of an unknown type is rejected"

## 12.4 commit before sending application data; the group still works afterwards
bob_group.process_message(wire(alice_group.create_psk_proposal("k")))
assert_raises(Melos::StateError) { bob_group.create_application_message("too early") }
result = alice_group.create_commit
bob_group.process_message(wire(result.commit))
alice_group.merge_commit(result.staged)
authenticated_content = alice_group.process_message(wire(bob_group.create_application_message("now")))
assert_equal "now", authenticated_content.content.application_data
puts "[pass] application data is refused while proposals are pending, and flows again after the commit"

## 12.2 proposal list rules
own_update = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::UPDATE, update: Melos::Struct::Update.create(leaf_node: alice_group.ratchet_tree.leaf_node_at(0)))
assert_raises(Melos::ProtocolError) { alice_group.create_commit(inline_proposals: [own_update]) }
puts "[pass] an Update from the committer is rejected"

carol_key_package = carol.create_key_package
add_carol = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::ADD, add: Melos::Struct::Add.create(key_package: carol_key_package.key_package))
assert_raises(Melos::ProtocolError) { alice_group.create_commit(inline_proposals: [add_carol, add_carol]) }
add_bob_again = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::ADD, add: Melos::Struct::Add.create(key_package: bob.create_key_package.key_package))
assert_raises(Melos::ProtocolError) { alice_group.create_commit(inline_proposals: [add_bob_again]) }
puts "[pass] two Adds for one client, or an Add for a current member, are rejected"

# ... unless the member is removed in the same commit: Bob is re-added with a fresh KeyPackage
remove_bob = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::REMOVE, remove: Melos::Struct::Remove.create(removed: 1))
bob_again = bob.create_key_package
add_bob_again = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::ADD, add: Melos::Struct::Add.create(key_package: bob_again.key_package))
result = alice_group.create_commit(inline_proposals: [remove_bob, add_bob_again])
bob_group.process_message(wire(result.commit)) # the old Bob sees himself removed
assert_equal false, bob_group.active?
alice_group.merge_commit(result.staged)
bob_group = bob.join_group(wire(result.welcome))   # the new Bob joins
assert_equal alice_group.epoch_authenticator, bob_group.epoch_authenticator
assert_equal 1, bob_group.leaf_index
puts "[pass] a Remove and an Add for the same client in one commit re-adds the member"

nonce = "n" * suite.kdf.n_h
psk_twice = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::PSK, psk: Melos::Struct::PreSharedKey.create(psk: Melos::Struct::PreSharedKeyID.create_external(psk_id: "k", psk_nonce: nonce)))
assert_raises(Melos::ProtocolError) { alice_group.create_commit(inline_proposals: [psk_twice, psk_twice]) }
gce = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::GROUP_CONTEXT_EXTENSIONS, group_context_extensions: Melos::Struct::GroupContextExtensions.create(extensions: []))
assert_raises(Melos::ProtocolError) { alice_group.create_commit(inline_proposals: [gce, gce]) }
puts "[pass] duplicate PreSharedKey IDs and multiple GroupContextExtensions proposals are rejected"

## 12.4.2 / 7.6 / 7.9.2 UpdatePath checks, against the path of a genuine commit from Alice
result = alice_group.create_commit
path = result.commit.public_message.content.commit.path
check = ->(update_path) { bob_group.send(:validate_update_path!, bob_group.ratchet_tree.dup, update_path, 0, [], bob_group.extensions) }
check.(path) # the genuine path passes
bob_leaf_key = bob_group.ratchet_tree.leaf_node_at(1).encryption_key
reused_key = Melos::Struct::UpdatePath.create(leaf_node: path.leaf_node, nodes: [Melos::Struct::UpdatePathNode.create(encryption_key: bob_leaf_key, encrypted_path_secret: path.nodes[0].encrypted_path_secret)])
assert_raises(Melos::ProtocolError) { check.(reused_key) }
no_ciphertexts = Melos::Struct::UpdatePath.create(leaf_node: path.leaf_node, nodes: [Melos::Struct::UpdatePathNode.create(encryption_key: path.nodes[0].encryption_key, encrypted_path_secret: [])])
assert_raises(Melos::ProtocolError) { check.(no_ciphertexts) }
old_leaf = Melos::Struct::UpdatePath.create(leaf_node: alice_group.ratchet_tree.leaf_node_at(0), nodes: path.nodes)
assert_raises(Melos::ProtocolError) { check.(old_leaf) } # wrong source, and the old encryption key
bob_group.process_message(wire(result.commit)) # and the genuine commit is still accepted end to end
alice_group.merge_commit(result.staged)
puts "[pass] an UpdatePath reusing a tree key, missing ciphertexts, or carrying a non-commit leaf is rejected"

## 10.1 / 7.3 KeyPackage and LeafNode validation, as the sender of an Add
now = Time.now.to_i
expired = carol.create_key_package(lifetime: Melos::Struct::Lifetime.create(not_before: now - 200, not_after: now - 100))
assert_raises(Melos::ProtocolError) { alice_group.create_add_proposal(expired.message) }
# the maximum lifetime is the application's to set (7.2); a group with a one-minute maximum rejects the default week
strict_group = alice.create_group("strict-#{suite_id}", max_leaf_node_lifetime: 60)
assert_raises(Melos::ProtocolError) { strict_group.create_add_proposal(carol.create_key_package.message) }
short_lived = carol.create_key_package(lifetime: Melos::Struct::Lifetime.create(not_before: now, not_after: now + 30))
strict_group.create_add_proposal(short_lived.message)
puts "[pass] a KeyPackage whose lifetime is expired, or longer than the group's maximum, is rejected"

other_suite = Melos::Capabilities.new
other_suite.cipher_suites = [suite_id + 1]
assert_raises(Melos::ProtocolError) { alice_group.create_add_proposal(carol.create_key_package(capabilities: Melos::Struct::Capabilities.import(other_suite)).message) }
no_credentials = Melos::Capabilities.new
no_credentials.credentials = []
assert_raises(Melos::ProtocolError) { alice_group.create_add_proposal(carol.create_key_package(capabilities: Melos::Struct::Capabilities.import(no_credentials)).message) }
puts "[pass] a KeyPackage whose capabilities lack the group's cipher suite or its own credential type is rejected"

good = carol.create_key_package
tampered = good.key_package.raw.dup
tampered[-1] = (tampered[-1].ord ^ 1).chr
assert_raises(Melos::ProtocolError) { alice_group.create_add_proposal(Melos::Struct::KeyPackage.new(tampered)) }
same_key = Melos::Struct::KeyPackage.create(cipher_suite: suite_id, init_key: good.key_package.leaf_node.encryption_key, leaf_node: good.key_package.leaf_node)
same_key.sign(carol.signature_private_key)
assert_raises(Melos::ProtocolError) { alice_group.create_add_proposal(same_key) }
puts "[pass] a KeyPackage with a bad signature, or whose init_key equals its leaf encryption key, is rejected"

leaf = good.key_package.leaf_node
wrong_source = Melos::Struct::LeafNode.create(
  encryption_key: leaf.encryption_key, signature_key: leaf.signature_key, credential: leaf.credential, capabilities: leaf.capabilities,
  leaf_node_source: C::LeafNodeSource::UPDATE, lifetime: nil, parent_hash: nil, extensions: [], signature: nil
)
wrong_source.sign(suite, carol.signature_private_key, alice_group.group_id, 2)
wrong_source_key_package = Melos::Struct::KeyPackage.create(cipher_suite: suite_id, init_key: good.key_package.init_key, leaf_node: wrong_source)
wrong_source_key_package.sign(carol.signature_private_key)
assert_raises(Melos::ProtocolError) { alice_group.create_add_proposal(wrong_source_key_package) }
bob_group.process_message(wire(alice_group.create_add_proposal(good.message))) # the untouched KeyPackage is fine
puts "[pass] a KeyPackage whose leaf node source is not key_package is rejected"

## 12.1.7 / 11.1 required_capabilities
rc_extension = ->(extension_types, credential_types) do
  rc = Melos::Struct::RequiredCapabilities.create(extension_types: extension_types.pack('S>*'), proposal_types: '', credential_types: credential_types.pack('S>*'))
  Melos::Struct::Extension.create(extension_type: C::ExtensionType::REQUIRED_CAPABILITIES, extension_data: rc.raw)
end
gce = ->(extensions) { Melos::Struct::Proposal.create(proposal_type: C::ProposalType::GROUP_CONTEXT_EXTENSIONS, group_context_extensions: Melos::Struct::GroupContextExtensions.create(extensions: extensions)) }
assert_raises(Melos::ProtocolError) { alice_group.create_commit(inline_proposals: [gce.([rc_extension.([0xF001], [])])]) }
result = alice_group.create_commit(inline_proposals: [gce.([rc_extension.([], [C::CredentialType::BASIC])])]) # also commits the pending Add of Carol
bob_group.process_message(wire(result.commit))
alice_group.merge_commit(result.staged)
carol_group = carol.join_group(wire(result.welcome))
assert_equal alice_group.epoch_authenticator, carol_group.epoch_authenticator
assert_equal 1, alice_group.extensions.size
puts "[pass] required_capabilities nobody supports is rejected; one everybody supports takes effect"

## 12.4.3.1 tree integrity, checked when joining; here against copies of Alice's tree (Alice, Bob, Carol, a blank leaf)
check_tree = ->(tree) { alice_group.send(:validate_tree!, tree, alice_group.extensions) }
check_tree.(alice_group.ratchet_tree) # the real tree passes
root = alice_group.ratchet_tree.root
real_parent = alice_group.ratchet_tree[root].parent_node
refute_nil real_parent, 'the test expects a non-blank root after the commits above'

tampered = alice_group.ratchet_tree.dup
tampered.nodes[root] = Melos::Struct::Node.new_parent_node(Melos::Struct::ParentNode.create(encryption_key: real_parent.encryption_key, parent_hash: "x" * 32, unmerged_leaves: real_parent.unmerged_leaves))
assert_raises(Melos::ProtocolError) { check_tree.(tampered) }
puts "[pass] a tree with a parent node that is not parent-hash valid is rejected"

duplicate = alice_group.ratchet_tree.dup
duplicate.nodes[2] = duplicate.nodes[0] # Bob's leaf replaced by a copy of Alice's
assert_raises(Melos::ProtocolError) { check_tree.(duplicate) }
puts "[pass] a tree where two leaves share their keys is rejected"

blank_unmerged = alice_group.ratchet_tree.dup
blank_unmerged.nodes[root] = Melos::Struct::Node.new_parent_node(Melos::Struct::ParentNode.create(encryption_key: real_parent.encryption_key, parent_hash: real_parent.parent_hash, unmerged_leaves: [3]))
assert_raises(Melos::ProtocolError) { check_tree.(blank_unmerged) }
puts "[pass] a tree whose parent lists a blank leaf as unmerged is rejected"

## 12.4.3 a client never participates in two groups with the same group_id
dave = Melos::Client.new(suite_id, identity: 'dave')
dave.create_group("shared-id")
assert_raises(Melos::StateError) { dave.create_group("shared-id") }
erin = Melos::Client.new(suite_id, identity: 'erin')
erin_group = erin.create_group("shared-id") # a different client, fine
erin_group.create_add_proposal(wire(dave.create_key_package.message))
result = erin_group.create_commit
assert_raises(Melos::StateError) { dave.join_group(wire(result.welcome)) }
assert_equal ["shared-id"], dave.groups.keys
puts "[pass] a client refuses to create or join a second group with a group_id it is already using"

## 7.3 an Update must bring a new encryption key, and 12.2 a committer must not commit its own Update
current = bob_group.ratchet_tree.leaf_node_at(1)
same_key = Melos::Struct::LeafNode.create(
  encryption_key: current.encryption_key, signature_key: current.signature_key, credential: current.credential, capabilities: current.capabilities,
  leaf_node_source: C::LeafNodeSource::UPDATE, lifetime: nil, parent_hash: nil, extensions: [], signature: nil
)
same_key.sign(suite, bob.signature_private_key, bob_group.group_id, 1)
same_key_update = bob_group.create_proposal(Melos::Struct::Proposal.create(proposal_type: C::ProposalType::UPDATE, update: Melos::Struct::Update.create(leaf_node: same_key)))
alice_group.process_message(wire(same_key_update))
assert_raises(Melos::ProtocolError) { alice_group.create_commit }
puts "[pass] an Update that keeps the old encryption key is rejected when committed"
# clear it out with a commit by Bob, who leaves his own Update out
result = bob_group.create_commit
alice_group.process_message(wire(result.commit))
bob_group.merge_commit(result.staged)
assert_equal alice_group.epoch_authenticator, bob_group.epoch_authenticator

## 9.2 a message key is handed out once: the same PrivateMessage cannot be decrypted twice
message = alice_group.create_application_message("once")
assert_equal "once", bob_group.process_message(wire(message)).content.application_data
assert_raises(Melos::StateError) { bob_group.process_message(wire(message)) }
puts "[pass] a replayed application message is refused"

## 15.3 a ratchet moves forward a bounded distance per message and keeps a bounded number of skipped keys
tree = Melos::SecretTree.new(suite, 2, "s" * suite.kdf.n_h, max_forward_distance: 5, out_of_order_tolerance: 2)
assert_raises(Melos::ProtocolError) { tree.ratchet_until_and_get(C::ContentType::APPLICATION, 0, 6) }
assert_equal 5, tree.ratchet_until_and_get(C::ContentType::APPLICATION, 0, 5)[2]
assert_equal [3, 4], tree.ratchet_for(C::ContentType::APPLICATION, 0).skipped_generations
assert_raises(Melos::StateError) { tree.ratchet_until_and_get(C::ContentType::APPLICATION, 0, 2) } # dropped from the window
assert_equal 3, tree.ratchet_until_and_get(C::ContentType::APPLICATION, 0, 3)[2]
assert_raises(Melos::StateError) { tree.ratchet_until_and_get(C::ContentType::APPLICATION, 0, 3) } # used
# and in a group: Bob accepts a jump of at most 1 generation
frank = Melos::Client.new(suite_id, identity: 'frank')
grace = Melos::Client.new(suite_id, identity: 'grace')
frank_group = frank.create_group("forward-distance")
frank_group.create_add_proposal(wire(grace.create_key_package.message))
result = frank_group.create_commit
grace_group = grace.join_group(wire(result.welcome), max_forward_distance: 1, max_past_epochs: 0)
frank_group.merge_commit(result.staged)
messages = 3.times.map { frank_group.create_application_message("m#{_1}") }
assert_raises(Melos::ProtocolError) { grace_group.process_message(wire(messages[2])) }
assert_equal "m1", grace_group.process_message(wire(messages[1])).content.application_data
# max_past_epochs: 0 keeps no earlier epoch
late = frank_group.create_application_message("late")
result = frank_group.create_commit
grace_group.process_message(wire(result.commit))
frank_group.merge_commit(result.staged)
assert_empty grace_group.past_epochs
assert_raises(Melos::ProtocolError) { grace_group.process_message(wire(late)) }
puts "[pass] ratchet jumps beyond the bound, dropped and used generations, and expired epochs are refused"

## 12.4.2 a member removed by a commit cannot follow the group further
result = alice_group.create_commit(inline_proposals: [Melos::Struct::Proposal.create(proposal_type: C::ProposalType::REMOVE, remove: Melos::Struct::Remove.create(removed: 1))])
bob_group.process_message(wire(result.commit))
alice_group.merge_commit(result.staged)
assert_equal false, bob_group.active?
assert_equal true, alice_group.active?
assert_raises(Melos::StateError) { bob_group.create_application_message("hello?") }
assert_raises(Melos::StateError) { bob_group.process_message(wire(alice_group.create_psk_proposal("k"))) }
puts "[pass] a removed member becomes inactive"
