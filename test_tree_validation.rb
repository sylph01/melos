require 'json'
require 'minitest'
require_relative 'ratchet_tree'
require_relative 'vec_base'
require_relative 'tree'
include Minitest::Assertions

class << self
attr_accessor :assertions
end
self.assertions = 0


vectors = JSON.load_file('test_vectors/tree-validation.json')
vectors.each_with_index do |vec, tree_index|
  puts "for tree num #{tree_index}:"
  tree = MLS::Struct::RatchetTree.parse(from_hex(vec['tree']))
  vec['resolutions'].each_with_index do |resolution, index|
    assert_equal resolution, MLS::Struct::RatchetTree.resolution(tree, index)
  end
end
