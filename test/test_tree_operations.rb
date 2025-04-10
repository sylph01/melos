require 'json'
require 'minitest'
require 'mls'
include Minitest::Assertions
include MLS::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

def check_tree_equality(left, right)
  assert_equal left.count, right.count
  left.each_with_index do |node, index|
    if node.nil?
      assert_nil right[index]
    else
      assert_equal node.raw, right[index].raw
    end
  end
end

vectors = JSON.load_file('test_vectors/tree-operations.json')
vectors.each do |vec|
  suite = MLS::Crypto::CipherSuite.new(vec['cipher_suite'])
  tree_before = MLS::Struct::RatchetTree.parse(from_hex(vec['tree_before']))
  tree_hash_before = from_hex(vec['tree_hash_before'])
  tree_after  = MLS::Struct::RatchetTree.parse(from_hex(vec['tree_after']))
  tree_hash_after = from_hex(vec['tree_hash_after'])

  # Actually the test vectors page does not say that you verify the "root node's tree hash"...
  assert_equal MLS::Struct::RatchetTree.root_tree_hash(suite, tree_before), tree_hash_before
  puts "[pass] Verify that the tree hash of tree_before matches tree_hash_before"
  prop = MLS::Struct::Proposal.new(from_hex(vec['proposal']))
  if prop.add
    # validate key package
    # TODO
    # create node to add
    node = MLS::Struct::Node.new_leaf_node(prop.add.key_package.leaf_node)
    MLS::Struct::RatchetTree.add_leaf_node(tree_before, node)
    # check tree equality
    check_tree_equality(tree_before, tree_after)
    puts "[pass] Application of Add"
  elsif prop.update
    proposal_sender = vec['proposal_sender']
    # create node to update
    node = MLS::Struct::Node.new_leaf_node(prop.update.leaf_node)
    MLS::Struct::RatchetTree.update_leaf_node(tree_before, node, proposal_sender)
    # check tree equality
    check_tree_equality(tree_before, tree_after)
    puts "[pass] Application of Update"
  elsif prop.remove
    removed = prop.remove.removed
    MLS::Struct::RatchetTree.remove_leaf_node(tree_before, removed)
    check_tree_equality(tree_before, tree_after)
    puts "[pass] Application of Remove"
  end

  assert_equal MLS::Struct::RatchetTree.root_tree_hash(suite, tree_after), tree_hash_after
  puts "[pass] Verify that the tree hash of candidate_tree_after matches tree_hash_after"
end
