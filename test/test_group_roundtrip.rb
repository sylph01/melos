require 'minitest'
require 'melos'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

# End-to-end exercise of the sending and receiving sides against each other, with no test vectors:
# Alice creates a group and adds Bob, Bob adds Carol, messages flow, a PSK is injected, then Alice
# removes Carol. Everything crosses between members as serialized MLSMessages.

# an MLSMessage as it arrives from the wire
def wire(message)
  Melos::Struct::MLSMessage.new(message.raw)
end

def deliver(group, message)
  group.process_message(wire(message))
end

def assert_same_epoch(*groups)
  groups.each_cons(2) do |a, b|
    assert_equal a.epoch, b.epoch
    assert_equal a.epoch_authenticator, b.epoch_authenticator
    assert_equal a.group_context.raw, b.group_context.raw
    assert_equal a.ratchet_tree.raw, b.ratchet_tree.raw
  end
end

suite_ids = ENV['TEST_ALL'] ? [1, 2, 3, 4, 5, 6, 7] : [1, 2]

suite_ids.each do |suite_id|
  puts "cipher suite #{suite_id}:"

  alice = Melos::Client.new(suite_id, identity: 'alice')
  bob = Melos::Client.new(suite_id, identity: 'bob')
  carol = Melos::Client.new(suite_id, identity: 'carol')

  ## Every KeyPackage gets its own leaf encryption key
  bob_key_package = bob.create_key_package
  another = bob.create_key_package
  refute_equal bob_key_package.key_package.leaf_node.encryption_key, another.key_package.leaf_node.encryption_key
  refute_equal bob_key_package.key_package.init_key, another.key_package.init_key
  assert_equal 2, bob.key_packages.size
  puts "[pass] KeyPackages of one client have distinct keys"

  ## Alice creates the group
  alice_group = alice.create_group("group-#{suite_id}")
  assert_equal 0, alice_group.epoch
  assert_equal 1, alice_group.ratchet_tree.n_leaves
  puts "[pass] Alice creates a group"

  ## Alice adds Bob: proposal, commit with a Welcome, Bob joins with the KeyPackage the Welcome names
  alice_group.create_add_proposal(wire(bob_key_package.message))
  result = alice_group.create_commit
  refute_nil result.welcome
  bob_group = bob.join_group(wire(result.welcome))
  alice_group.merge_commit(result.staged)
  assert_same_epoch(alice_group, bob_group)
  assert_equal 1, alice_group.epoch
  assert_equal 1, bob_group.leaf_index
  assert_equal [another.ref], bob.key_packages.keys # the used KeyPackage is forgotten, the other remains
  assert_equal true, bob_group.private_tree.consistent?(bob_group.ratchet_tree)
  assert_equal true, alice_group.private_tree.consistent?(alice_group.ratchet_tree)
  puts "[pass] Alice adds Bob and Bob joins from the Welcome"

  ## 9.2: once an epoch is current, the secrets that produced it are gone; what the epoch needs remains
  [alice_group, bob_group].each do |group|
    assert_nil group.epoch_secrets.epoch_secret
    assert_nil group.epoch_secrets.joiner_secret
    assert_nil group.epoch_secrets.psk_secret
    refute_nil group.epoch_secrets.membership_key
    refute_nil group.epoch_secrets.init_secret
    assert_nil result.staged.path_secrets
  end
  puts "[pass] Consumed secrets are dropped once the epoch is current"

  ## Exported secrets agree between members and depend on label, context and length
  exported = alice_group.export_secret("app", "ctx", 32)
  assert_equal exported, bob_group.export_secret("app", "ctx", 32)
  assert_equal 32, exported.bytesize
  refute_equal exported, alice_group.export_secret("other", "ctx", 32)
  refute_equal exported, alice_group.export_secret("app", "other", 32)
  assert_equal 16, alice_group.export_secret("app", "ctx", 16).bytesize
  puts "[pass] Exported secrets agree between members"

  ## Bob sends an application message, Alice reads it
  authenticated_content = deliver(alice_group, bob_group.create_application_message("hello from bob"))
  assert_equal "hello from bob", authenticated_content.content.application_data
  assert_equal 1, authenticated_content.content.sender.leaf_index
  puts "[pass] Bob's application message decrypts for Alice"

  ## Alice sends an empty commit (update path only), Bob processes it
  result = alice_group.create_commit
  assert_nil result.welcome
  deliver(bob_group, result.commit)
  alice_group.merge_commit(result.staged)
  assert_same_epoch(alice_group, bob_group)
  assert_equal 2, alice_group.epoch
  puts "[pass] Alice's empty commit advances both members"

  ## Bob adds Carol: Alice sees the proposal first, then the commit by reference; Carol joins
  carol_key_package = carol.create_key_package
  deliver(alice_group, bob_group.create_add_proposal(wire(carol_key_package.message)))
  # 12.4: having seen a proposal, Alice must not send application data before it is committed
  assert_raises(Melos::StateError) { alice_group.create_application_message("too early") }
  result = bob_group.create_commit
  deliver(alice_group, result.commit)
  bob_group.merge_commit(result.staged)
  carol_group = carol.join_group(wire(result.welcome))
  assert_same_epoch(alice_group, bob_group, carol_group)
  assert_equal 2, carol_group.leaf_index
  assert_equal 4, carol_group.ratchet_tree.n_leaves
  assert_empty carol.key_packages
  puts "[pass] Bob adds Carol by referencing his proposal, Carol joins"

  ## Alice's application message reaches both, as a private message with padding
  message = alice_group.create_application_message("hello everyone", authenticated_data: "aad", padding_size: 13)
  [bob_group, carol_group].each do |group|
    authenticated_content = deliver(group, message)
    assert_equal "hello everyone", authenticated_content.content.application_data
    assert_equal "aad", authenticated_content.content.authenticated_data
  end
  puts "[pass] Alice's application message decrypts for Bob and Carol"

  ## 9.1: application messages that arrive out of order still decrypt, each once
  first = alice_group.create_application_message("first")
  second = alice_group.create_application_message("second")
  assert_equal "second", deliver(bob_group, second).content.application_data
  assert_equal "first", deliver(bob_group, first).content.application_data
  assert_raises(Melos::StateError) { deliver(bob_group, first) }
  [first, second].each { deliver(carol_group, _1) }
  puts "[pass] Application messages delivered in reverse order decrypt"

  ## 15.3: an application message of the previous epoch decrypts after a commit; a proposal does not
  late = carol_group.create_application_message("sent before the commit")
  stale_update = carol_group.create_update_proposal
  carol_group.instance_variable_get(:@pending_proposals).clear # Carol drops her Update; nobody else saw it
  epoch_before = alice_group.epoch
  result = alice_group.create_commit
  [bob_group, carol_group].each { deliver(_1, result.commit) }
  alice_group.merge_commit(result.staged)
  assert_same_epoch(alice_group, bob_group, carol_group)
  assert_includes bob_group.past_epochs, epoch_before
  authenticated_content = deliver(bob_group, late)
  assert_equal "sent before the commit", authenticated_content.content.application_data
  assert_equal epoch_before, authenticated_content.content.epoch
  assert_raises(Melos::ProtocolError) { deliver(bob_group, stale_update) }
  # with the group's default of two past epochs, the message is refused once three more epochs have passed
  late = carol_group.create_application_message("much later")
  3.times do
    result = alice_group.create_commit
    [bob_group, carol_group].each { deliver(_1, result.commit) }
    alice_group.merge_commit(result.staged)
  end
  assert_equal Melos::Group::DEFAULT_MAX_PAST_EPOCHS, bob_group.past_epochs.size
  assert_raises(Melos::ProtocolError) { deliver(bob_group, late) }
  # a retained epoch keeps only what its messages need (9.2)
  past = bob_group.instance_variable_get(:@past_epochs).values.first
  assert_raises(ArgumentError) { past.epoch_secrets.init_secret }
  puts "[pass] A previous epoch's application message decrypts; handshake messages and expired epochs are refused"

  ## Bob proposes an Update; Alice commits it; Bob's new leaf key is in use on both sides
  old_key = bob_group.ratchet_tree.leaf_node_at(1).encryption_key
  update = bob_group.create_update_proposal
  deliver(alice_group, update)
  deliver(carol_group, update)
  result = alice_group.create_commit
  [bob_group, carol_group].each { deliver(_1, result.commit) }
  alice_group.merge_commit(result.staged)
  assert_same_epoch(alice_group, bob_group, carol_group)
  refute_equal old_key, bob_group.ratchet_tree.leaf_node_at(1).encryption_key
  assert_equal true, bob_group.private_tree.consistent?(bob_group.ratchet_tree)
  authenticated_content = deliver(bob_group, alice_group.create_application_message("to the new Bob"))
  assert_equal "to the new Bob", authenticated_content.content.application_data
  puts "[pass] Bob's Update is committed by Alice and Bob holds the new key"

  ## Bob proposes another Update but commits himself: his own Update is left out, his path replaces the leaf
  update = bob_group.create_update_proposal
  deliver(alice_group, update)
  deliver(carol_group, update)
  result = bob_group.create_commit
  assert_empty result.commit.public_message.content.commit.proposals
  [alice_group, carol_group].each { deliver(_1, result.commit) }
  bob_group.merge_commit(result.staged)
  assert_same_epoch(alice_group, bob_group, carol_group)
  assert_equal true, bob_group.private_tree.consistent?(bob_group.ratchet_tree)
  puts "[pass] A committer's own Update is superseded by its path"

  ## A commit that only adds may omit the UpdatePath (12.4): Dave joins without a path secret
  dave = Melos::Client.new(suite_id, identity: 'dave')
  add_dave = alice_group.create_add_proposal(wire(dave.create_key_package.message))
  deliver(bob_group, add_dave)
  deliver(carol_group, add_dave)
  result = alice_group.create_commit(path: :if_required)
  assert_nil result.commit.public_message.content.commit.path
  deliver(bob_group, result.commit)
  deliver(carol_group, result.commit)
  alice_group.merge_commit(result.staged)
  dave_group = dave.join_group(wire(result.welcome))
  assert_same_epoch(alice_group, bob_group, carol_group, dave_group)
  assert_equal 3, dave_group.leaf_index
  # Dave can follow a full commit afterwards
  result = bob_group.create_commit
  [alice_group, carol_group, dave_group].each { deliver(_1, result.commit) }
  bob_group.merge_commit(result.staged)
  assert_same_epoch(alice_group, bob_group, carol_group, dave_group)
  puts "[pass] A path-less Add commit is accepted and the joiner keeps up"

  ## ... but a Remove forces a path even with path: :if_required
  remove_dave = alice_group.create_remove_proposal(3)
  [bob_group, carol_group, dave_group].each { deliver(_1, remove_dave) }
  result = alice_group.create_commit(path: :if_required)
  refute_nil result.commit.public_message.content.commit.path
  [bob_group, carol_group, dave_group].each { deliver(_1, result.commit) }
  alice_group.merge_commit(result.staged)
  assert_same_epoch(alice_group, bob_group, carol_group)
  assert_equal false, dave_group.active?
  puts "[pass] A Remove commit always carries a path"

  ## Carol injects a PSK every member knows: proposal to both, commit, everyone advances
  [alice, bob, carol].each { _1.add_external_psk("shared-psk", "p" * 32) }
  psk_proposal = carol_group.create_psk_proposal("shared-psk")
  deliver(alice_group, psk_proposal)
  deliver(bob_group, psk_proposal)
  result = carol_group.create_commit
  deliver(alice_group, result.commit)
  deliver(bob_group, result.commit)
  carol_group.merge_commit(result.staged)
  assert_same_epoch(alice_group, bob_group, carol_group)
  puts "[pass] A commit with an external PSK proposal advances every member"

  ## Alice removes Carol: Bob caches the proposal and processes the commit
  remove_proposal = alice_group.create_remove_proposal(2)
  deliver(bob_group, remove_proposal)
  deliver(carol_group, remove_proposal) # Carol needs the proposal too, to resolve the commit that removes her
  result = alice_group.create_commit
  assert_nil result.welcome
  deliver(bob_group, result.commit)
  alice_group.merge_commit(result.staged)
  assert_same_epoch(alice_group, bob_group)
  assert_equal 2, alice_group.ratchet_tree.n_leaves
  assert_nil alice_group.ratchet_tree.leaf_node_at(2)
  # 9.2: Bob's private tree holds exactly the keys for his leaf and the (fresh) root, nothing from the old nodes
  assert_equal [1, 2], bob_group.private_tree.node_indexes
  assert_equal true, bob_group.private_tree.consistent?(bob_group.ratchet_tree)
  puts "[pass] Alice removes Carol and the tree shrinks back to two leaves"

  ## Carol processes the commit that removed her: she sees it, and can no longer send
  deliver(carol_group, result.commit)
  assert_equal false, carol_group.active?
  assert_raises(Melos::StateError) { carol_group.create_application_message("am I still here?") }
  assert_raises(Melos::StateError) { carol_group.create_commit }
  puts "[pass] Carol learns she was removed and stops sending"

  ## A commit referencing a proposal Alice never received is rejected; Bob does not merge it
  bob_group.create_psk_proposal("shared-psk")
  result = bob_group.create_commit
  assert_raises(Melos::ProtocolError) { deliver(alice_group, result.commit) }
  puts "[pass] A commit referencing an unseen proposal is rejected"

  ## Both are still in the same epoch. Bob has a proposal pending and must commit before he can send (12.4);
  ## Alice never saw it, so she can.
  assert_raises(Melos::StateError) { bob_group.create_application_message("still here?") }
  authenticated_content = deliver(bob_group, alice_group.create_application_message("still here"))
  assert_equal "still here", authenticated_content.content.application_data
  puts "[pass] Messages still flow afterwards"
end
