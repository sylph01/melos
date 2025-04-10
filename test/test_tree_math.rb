require 'json'
require 'minitest'
require 'mls'
include Minitest::Assertions
include MLS::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

# test all vectors anyways
tree_math_vectors = JSON.parse(File.read('test_vectors/tree-math.json'))

tree_math_vectors.each do |tmv|
  n_leaves = tmv['n_leaves']
  puts "For leaves #{n_leaves}:"
  n_nodes  = tmv['n_nodes']
  assert_equal n_nodes, MLS::Tree.node_width(n_leaves)
  puts "[s] MLS::Tree.node_width"

  assert_equal tmv['root'], MLS::Tree.root(n_leaves)
  puts "[s] MLS::Tree.root"

  tmv['left'].each_with_index do |value, index|
    if value.nil?
      assert_raises ArgumentError do
        MLS::Tree.left(index)
      end
    else
      assert_equal value, MLS::Tree.left(index)
    end
  end
  puts "[s] MLS::Tree.left"

  tmv['right'].each_with_index do |value, index|
    if value.nil?
      assert_raises ArgumentError do
        MLS::Tree.right(index)
      end
    else
      assert_equal value, MLS::Tree.right(index)
    end
  end
  puts "[s] MLS::Tree.right"

  tmv['parent'].each_with_index do |value, index|
    if value.nil?
      assert_raises ArgumentError do
        assert_nil MLS::Tree.parent(index, n_leaves)
      end
    else
      assert_equal value, MLS::Tree.parent(index, n_leaves)
    end
  end
  puts "[s] MLS::Tree.parent"

  tmv['sibling'].each_with_index do |value, index|
    if value.nil?
      assert_raises ArgumentError do
        assert_nil MLS::Tree.parent(index, n_leaves)
      end
    else
      assert_equal value, MLS::Tree.sibling(index, n_leaves)
    end
  end
  puts "[s] MLS::Tree.sibling"
end
