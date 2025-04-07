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

# TODO: move to PrivateTree class
def consistent?(private_tree, public_tree, suite)
  result = true
  private_tree.each_with_index do |private_node, private_node_index|
    if !private_node.nil?
      public_node = public_tree[private_node_index]
      result = false and next if public_node.nil?
      # check if private key corresponds to public key
      resulf = false and next if !MLS::Crypto.encapsulation_key_pair_corresponds?(suite, private_node[:encryption_priv], public_node.public_encryption_key)
    end
  end
  result
end

vectors = JSON.load_file('test_vectors/treekem.json')
vectors.each_with_index do |vector, tree_index|
  suite = MLS::Crypto::CipherSuite.new(vector['cipher_suite'])
  puts "for tree index #{tree_index}, cipher suite ID #{vector['cipher_suite']}:"

  confirmed_transcript_hash = from_hex(vector['confirmed_transcript_hash'])
  group_id = from_hex(vector['group_id'])
  epoch = vector['epoch']

  ratchet_tree = MLS::Struct::RatchetTree.parse(from_hex(vector['ratchet_tree']))

  private_treekem_state = []

  vector['leaves_private'].each do |leaf_private|
    leaf_index = leaf_private['index']
    node_index_of_leaf = leaf_index * 2
    encryption_priv = from_hex(leaf_private['encryption_priv']) # HPKE private key
    signature_priv  = from_hex(leaf_private['signature_priv'])  # signature private key
    # Associate encryption_priv and signature_priv with the leaf node
    private_treekem_state[node_index_of_leaf] = {
      encryption_priv: encryption_priv,
      signature_priv: signature_priv
    }
    # For each entry in path_secrets:
    leaf_private['path_secrets'].each do |ps|
      ## Identify the node in the tree with node index node in the array representation of the tree
      public_node = ratchet_tree[ps['node']]
      ## Set the private value at this node based on path_secret
      path_secret = ps['path_secret']
    end
  end
  # Verify that the resulting private state leaf_private[i] is consistent with the ratchet_tree,
  # in the sense that for every node in the private state, the corresponding node in the tree is
  # (a) not blank and (b) contains the public key corresponding to the private key in the private state.
  assert_equal true, consistent?(private_treekem_state, ratchet_tree, suite)
  puts "[pass] Verify that the resulting private state leaf_private[i] is consistent with the ratchet_tree"
end
