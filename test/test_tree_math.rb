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
tree_math_vectors = JSON.parse(File.read('test_vectors/tree-math.json'))

tree_math_vectors.each do |tmv|
  n_leaves = tmv['n_leaves']
  puts "For leaves #{n_leaves}:"
  n_nodes  = tmv['n_nodes']
  assert_equal n_nodes, Melos::Tree.node_width(n_leaves)
  puts "[s] Melos::Tree.node_width"

  assert_equal tmv['root'], Melos::Tree.root(n_leaves)
  puts "[s] Melos::Tree.root"

  tmv['left'].each_with_index do |value, index|
    if value.nil?
      assert_raises ArgumentError do
        Melos::Tree.left(index)
      end
    else
      assert_equal value, Melos::Tree.left(index)
    end
  end
  puts "[s] Melos::Tree.left"

  tmv['right'].each_with_index do |value, index|
    if value.nil?
      assert_raises ArgumentError do
        Melos::Tree.right(index)
      end
    else
      assert_equal value, Melos::Tree.right(index)
    end
  end
  puts "[s] Melos::Tree.right"

  tmv['parent'].each_with_index do |value, index|
    if value.nil?
      assert_raises ArgumentError do
        assert_nil Melos::Tree.parent(index, n_leaves)
      end
    else
      assert_equal value, Melos::Tree.parent(index, n_leaves)
    end
  end
  puts "[s] Melos::Tree.parent"

  tmv['sibling'].each_with_index do |value, index|
    if value.nil?
      assert_raises ArgumentError do
        assert_nil Melos::Tree.parent(index, n_leaves)
      end
    else
      assert_equal value, Melos::Tree.sibling(index, n_leaves)
    end
  end
  puts "[s] Melos::Tree.sibling"
end
