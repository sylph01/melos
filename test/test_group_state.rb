require 'minitest'
require 'melos'
include Minitest::Assertions
include Melos::Util

class << self
  attr_accessor :assertions
end
self.assertions = 0

puts "Testing GroupState..."

# Create mock objects for testing
dummy_group_context = Melos::Struct::GroupContext.allocate
dummy_group_context.instance_variable_set(:@epoch, 42)
dummy_group_context.instance_variable_set(:@group_id, "test_group_id")
dummy_group_context.instance_variable_set(:@cipher_suite, 0x0001)
dummy_group_context.instance_variable_set(:@version, 1)
dummy_group_context.instance_variable_set(:@tree_hash, "tree_hash")
dummy_group_context.instance_variable_set(:@confirmed_transcript_hash, "transcript_hash")
dummy_group_context.instance_variable_set(:@extensions, [])

dummy_tree = Object.new
dummy_key_schedule = Object.new
dummy_secret_tree = Object.new
dummy_secret_tree.define_singleton_method(:current_generation) { 10 }
dummy_membership_key = "membership_key"
dummy_signature_private_key = "signature_private_key"
leaf_index = 5

# Test GroupState Creation
puts "Testing GroupState initialization..."
group_state = Melos::GroupState.new(
  group_context: dummy_group_context,
  tree: dummy_tree,
  key_schedule: dummy_key_schedule,
  secret_tree: dummy_secret_tree,
  membership_key: dummy_membership_key,
  signature_private_key: dummy_signature_private_key,
  leaf_index: leaf_index
)

assert_equal Melos::GroupState, group_state.class
assert_equal dummy_group_context, group_state.group_context
assert_equal dummy_tree, group_state.tree
assert_equal dummy_key_schedule, group_state.key_schedule
assert_equal dummy_secret_tree, group_state.secret_tree
assert_equal dummy_membership_key, group_state.membership_key
assert_equal dummy_signature_private_key, group_state.signature_private_key
assert_equal leaf_index, group_state.leaf_index
puts "[✓] GroupState initialization works"

# Test Convenience Methods
puts "Testing GroupState convenience methods..."
assert_equal 42, group_state.epoch
assert_equal "test_group_id", group_state.group_id
assert_equal 0x0001, group_state.cipher_suite
assert_equal 1, group_state.version
assert_equal "tree_hash", group_state.tree_hash
assert_equal "transcript_hash", group_state.confirmed_transcript_hash
assert_equal [], group_state.extensions
puts "[✓] Convenience methods work"

# Test create_sender
puts "Testing create_sender method..."
sender = group_state.create_sender
assert_equal Melos::Struct::Sender, sender.class
assert_equal Melos::Constants::SenderType::MEMBER, sender.sender_type
assert_equal leaf_index, sender.leaf_index
puts "[✓] create_sender works"

# Test current_generation
puts "Testing current_generation method..."
assert_equal 10, group_state.current_generation
puts "[✓] current_generation works"

# Test validation
puts "Testing validate_for_message_creation!..."
# Should not raise with valid state
group_state.validate_for_message_creation!
puts "[✓] Validation passes with complete state"

# Test validation failures
puts "Testing validation failures..."
invalid_group_state = Melos::GroupState.new(
  group_context: nil,
  tree: dummy_tree,
  key_schedule: dummy_key_schedule,
  secret_tree: dummy_secret_tree,
  membership_key: dummy_membership_key,
  signature_private_key: dummy_signature_private_key,
  leaf_index: leaf_index
)

begin
  invalid_group_state.validate_for_message_creation!
  assert false, "Should have raised an error"
rescue => e
  assert_equal "Group context is required", e.message
end
puts "[✓] Validation correctly fails with missing group context"

# Test with missing tree
invalid_group_state2 = Melos::GroupState.new(
  group_context: dummy_group_context,
  tree: nil,
  key_schedule: dummy_key_schedule,
  secret_tree: dummy_secret_tree,
  membership_key: dummy_membership_key,
  signature_private_key: dummy_signature_private_key,
  leaf_index: leaf_index
)

begin
  invalid_group_state2.validate_for_message_creation!
  assert false, "Should have raised an error"
rescue => e
  assert_equal "Tree is required", e.message
end
puts "[✓] Validation correctly fails with missing tree"

# Test with missing leaf_index
invalid_group_state3 = Melos::GroupState.new(
  group_context: dummy_group_context,
  tree: dummy_tree,
  key_schedule: dummy_key_schedule,
  secret_tree: dummy_secret_tree,
  membership_key: dummy_membership_key,
  signature_private_key: dummy_signature_private_key,
  leaf_index: nil
)

begin
  invalid_group_state3.validate_for_message_creation!
  assert false, "Should have raised an error"
rescue => e
  assert_equal "Leaf index is required", e.message
end
puts "[✓] Validation correctly fails with missing leaf index"

puts "All GroupState tests passed! ✅"
