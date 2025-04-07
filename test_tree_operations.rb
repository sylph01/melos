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
    check_tree_equality(tree_before, tree_after)
    puts "[pass] Application of Add"
  elsif prop.update

  elsif prop.remove

  end
end
