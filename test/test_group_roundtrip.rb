require 'minitest'
require 'melos'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

# End-to-end exercise of the sending and receiving sides against each other, with no test vectors:
# Alice creates a group and adds Bob, Bob adds Carol, messages flow, then Alice removes Carol.
# Everything crosses between members as serialized MLSMessages.

def member(suite_id, name)
  client = Melos::Client.new(suite_id)
  key_package = Melos::KeyPackage.new(client)
  leaf_node = key_package.create_leaf_node(name)
  {
    client: client,
    key_package: key_package,
    leaf_node: leaf_node,
    key_package_message: Melos::Struct::MLSMessage.create(key_package: key_package.create_message(leaf_node))
  }
end

def join(suite, member, welcome)
  Melos::Group.from_welcome(
    suite, Melos::Struct::MLSMessage.new(welcome.raw),
    key_package: Melos::Struct::MLSMessage.new(member[:key_package_message].raw),
    init_private_key: member[:key_package].init_private_key,
    encryption_private_key: member[:client].encryption_private_key,
    signature_private_key: member[:client].signature_private_key
  )
end

# deliver an MLSMessage to a group as the bytes that would come off the wire
def deliver(group, message)
  group.process_message(Melos::Struct::MLSMessage.new(message.raw))
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
  suite = Melos::Crypto::CipherSuite.new(suite_id)
  puts "cipher suite #{suite_id}:"

  alice = member(suite_id, 'alice')
  bob = member(suite_id, 'bob')
  carol = member(suite_id, 'carol')

  ## Alice creates the group
  alice_group = Melos::Group.create(
    suite, "group-#{suite_id}", alice[:leaf_node],
    encryption_private_key: alice[:client].encryption_private_key,
    signature_private_key: alice[:client].signature_private_key
  )
  assert_equal 0, alice_group.epoch
  assert_equal 1, alice_group.ratchet_tree.n_leaves
  puts "[pass] Alice creates a group"

  ## Alice adds Bob: proposal, commit with a Welcome, Bob joins
  alice_group.create_add_proposal(bob[:key_package_message])
  result = alice_group.create_commit
  refute_nil result.welcome
  bob_group = join(suite, bob, result.welcome)
  alice_group.merge_commit(result.staged)
  assert_same_epoch(alice_group, bob_group)
  assert_equal 1, alice_group.epoch
  assert_equal 1, bob_group.leaf_index
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
  deliver(alice_group, bob_group.create_add_proposal(carol[:key_package_message]))
  result = bob_group.create_commit
  deliver(alice_group, result.commit)
  bob_group.merge_commit(result.staged)
  carol_group = join(suite, carol, result.welcome)
  assert_same_epoch(alice_group, bob_group, carol_group)
  assert_equal 2, carol_group.leaf_index
  assert_equal 4, carol_group.ratchet_tree.n_leaves
  puts "[pass] Bob adds Carol by referencing his proposal, Carol joins"

  ## Alice's application message reaches both, as a private message with padding
  message = alice_group.create_application_message("hello everyone", authenticated_data: "aad", padding_size: 13)
  [bob_group, carol_group].each do |group|
    authenticated_content = deliver(group, message)
    assert_equal "hello everyone", authenticated_content.content.application_data
    assert_equal "aad", authenticated_content.content.authenticated_data
  end
  puts "[pass] Alice's application message decrypts for Bob and Carol"

  ## Alice removes Carol: Bob caches the proposal and processes the commit
  deliver(bob_group, alice_group.create_remove_proposal(2))
  result = alice_group.create_commit
  assert_nil result.welcome
  deliver(bob_group, result.commit)
  alice_group.merge_commit(result.staged)
  assert_same_epoch(alice_group, bob_group)
  assert_equal 2, alice_group.ratchet_tree.n_leaves
  assert_nil alice_group.ratchet_tree.leaf_node_at(2)
  puts "[pass] Alice removes Carol and the tree shrinks back to two leaves"

  ## Bob can still talk to Alice afterwards
  authenticated_content = deliver(alice_group, bob_group.create_application_message("still here"))
  assert_equal "still here", authenticated_content.content.application_data
  puts "[pass] Messages still flow after the removal"
end
