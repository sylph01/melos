require 'json'
require 'minitest'
require 'mls'
include Minitest::Assertions
include MLS::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

if ENV['TEST_ALL']
  vectors = JSON.load_file('test_vectors/tree-validation.json')
else
  vectors = JSON.load_file('test_vectors/tree-validation.json').select { _1['cipher_suite'] == 1 }
end

vectors.each_with_index do |vec, tree_index|
  suite = MLS::Crypto::CipherSuite.new(vec['cipher_suite'])
  puts "for tree num #{tree_index}:"

  tree = MLS::Struct::RatchetTree.parse(from_hex(vec['tree']))
  group_id = from_hex(vec['tree'])

  vec['resolutions'].each_with_index do |resolution, index|
    assert_equal resolution, MLS::Tree.resolution(tree, index)
  end
  puts "[pass] Resolutions of each node of the tree matches"

  vec['tree_hashes'].each_with_index do |tree_hash, index|
    assert_equal tree_hash, to_hex(MLS::Struct::RatchetTree.tree_hash(tree, index, suite))
  end
  puts "[pass] Tree hash calculation matches"

  assert_equal true, MLS::Struct::RatchetTree.verify_parent_hash_of_tree(tree, suite)
  puts "[pass] All parent nodes are parent-hash valid (a.k.a. can be chained back to a leaf node)"

  tree.select.with_index { |n, n_idx| MLS::Tree.leaf?(n_idx) }.map.with_index do |node, node_index|
    if node.nil?
      true
    else
      leaf_node = node.leaf_node

      leaf_node.verify(suite, group_id, (node_index / 2))
    end
  end.all?(true)
  puts "[pass] Verify the signatures on all leaves of tree using the provided group_id as context"
end
