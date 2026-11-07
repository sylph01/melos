require 'json'
require 'minitest'
require 'melos'
include Minitest::Assertions
include Melos::Util

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
  suite = Melos::Crypto::CipherSuite.new(vec['cipher_suite'])
  puts "for tree num #{tree_index}:"

  tree = Melos::RatchetTree.parse(suite, from_hex(vec['tree']))
  group_id = from_hex(vec['group_id'])

  vec['resolutions'].each_with_index do |resolution, index|
    assert_equal resolution, tree.resolution(index)
  end
  puts "[pass] Resolutions of each node of the tree matches"

  vec['tree_hashes'].each_with_index do |tree_hash, index|
    assert_equal tree_hash, to_hex(tree.tree_hash(index))
  end
  puts "[pass] Tree hash calculation matches"

  assert_equal true, tree.parent_hash_valid?
  puts "[pass] All parent nodes are parent-hash valid (a.k.a. can be chained back to a leaf node)"

  tree.each_leaf_node do |leaf_node, leaf_index|
    assert_equal true, leaf_node.verify(suite, group_id, leaf_index)
  end
  puts "[pass] Verify the signatures on all leaves of tree using the provided group_id as context"
end
