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
  suite = MLS::Crypto::CipherSuite.new(vec['cipher_suite'])
  puts "for tree num #{tree_index}:"

  tree = MLS::Struct::RatchetTree.parse(from_hex(vec['tree']))

  vec['resolutions'].each_with_index do |resolution, index|
    assert_equal resolution, MLS::Struct::RatchetTree.resolution(tree, index)
  end
  puts "[pass] Resolutions of each node of the tree matches"

  vec['tree_hashes'].each_with_index do |tree_hash, index|
    puts "index #{index}:"
    assert_equal tree_hash, to_hex(MLS::Struct::RatchetTree.tree_hash(tree, index, suite))
  end
  puts "[pass] Tree hash calculation matches"
end
