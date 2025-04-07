require 'json'
require 'minitest'
require_relative 'ratchet_tree'
require_relative 'vec_base'
require_relative 'tree'
require_relative 'structs'
include Minitest::Assertions

class << self
attr_accessor :assertions
end
self.assertions = 0

vectors = JSON.load_file('test_vectors/tree-operations.json')
vectors.each do |vec|
  tree_before = MLS::Struct::RatchetTree.parse(from_hex(vec['tree_before']))
  tree_after  = MLS::Struct::RatchetTree.parse(from_hex(vec['tree_after']))
  prop = MLSStruct::Proposal.new(from_hex(vec['proposal']))
  if prop.add
    # validate key package
    # TODO
    # create node to add
    node = MLSStruct::Node.new_leaf_node(prop.add.key_package.leaf_node)
    MLS::Struct::RatchetTree.add_leaf_node(tree_before, node)
    # check tree equality
    assert_equal tree_before.count, tree_after.count
    tree_before.each_with_index do |node, index|
      if node.nil?
        assert_nil tree_after[index]
      else
        assert_equal node&.raw, tree_after[index]&.raw
      end
    end
    puts "[pass] Application of Add"
  end
end
