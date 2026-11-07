require 'json'
require 'minitest'
require 'melos'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

# test all vectors anyways
vectors = JSON.load_file('test_vectors/tree-operations.json')

vectors.each do |vec|
  suite = Melos::Crypto::CipherSuite.new(vec['cipher_suite'])
  tree = Melos::RatchetTree.parse(suite, from_hex(vec['tree_before']))

  # Actually the test vectors page does not say that you verify the "root node's tree hash"...
  assert_equal from_hex(vec['tree_hash_before']), tree.root_tree_hash
  puts "[pass] Verify that the tree hash of tree_before matches tree_hash_before"

  prop = Melos::Struct::Proposal.new(from_hex(vec['proposal']))
  if prop.add
    # TODO: validate key package
    tree.add_leaf_node(prop.add.key_package.leaf_node)
    puts "[pass] Application of Add"
  elsif prop.update
    tree.update_leaf_node(vec['proposal_sender'], prop.update.leaf_node)
    puts "[pass] Application of Update"
  elsif prop.remove
    tree.remove_leaf_node(prop.remove.removed)
    puts "[pass] Application of Remove"
  end

  assert_equal from_hex(vec['tree_hash_after']), tree.root_tree_hash
  puts "[pass] Verify that the tree hash of candidate_tree_after matches tree_hash_after"
  assert_equal vec['tree_after'], to_hex(tree.raw)
  puts "[pass] candidate_tree_after serializes to tree_after"
end
