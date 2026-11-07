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
  assert_raises(ArgumentError) { alice_group.create_application_message("too early") }
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
  puts "[pass] Alice removes Carol and the tree shrinks back to two leaves"

  ## Carol processes the commit that removed her: she sees it, and can no longer send
  deliver(carol_group, result.commit)
  assert_equal false, carol_group.active?
  assert_raises(ArgumentError) { carol_group.create_application_message("am I still here?") }
  assert_raises(ArgumentError) { carol_group.create_commit }
  puts "[pass] Carol learns she was removed and stops sending"

  ## A commit referencing a proposal Alice never received is rejected; Bob does not merge it
  bob_group.create_psk_proposal("shared-psk")
  result = bob_group.create_commit
  assert_raises(ArgumentError) { deliver(alice_group, result.commit) }
  puts "[pass] A commit referencing an unseen proposal is rejected"

  ## Both are still in the same epoch. Bob has a proposal pending and must commit before he can send (12.4);
  ## Alice never saw it, so she can.
  assert_raises(ArgumentError) { bob_group.create_application_message("still here?") }
  authenticated_content = deliver(bob_group, alice_group.create_application_message("still here"))
  assert_equal "still here", authenticated_content.content.application_data
  puts "[pass] Messages still flow afterwards"
end
