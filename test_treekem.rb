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

# maybe in RatchetTree class?
def verify_parent_hash_of_path(suite, ratchet_tree, leaf_index_from, update_path)
  filtered_direct_path = MLS::Tree.filtered_direct_path(ratchet_tree, leaf_index_from)
  nodes_from_update_path = update_path.nodes
  # count down from root, calculate parent hash
  calculated_parent_hash = ""
  # node_index = MLS::Tree.root(MLS::Tree.n_leaves(ratchet_tree))
  # puts "fdp count: #{filtered_direct_path.count}"
  # puts "update path count: #{nodes_from_update_path.count}"
  (filtered_direct_path.count - 1).downto(0) do |path_index|
    node_index = filtered_direct_path[path_index]
    leaf_node_index = leaf_index_from * 2
    sibling_node_index = MLS::Tree.sibling_from_leaf(leaf_node_index, node_index, MLS::Tree.n_leaves(ratchet_tree))
    encryption_key = nodes_from_update_path[path_index].encryption_key
    sibling_node = ratchet_tree[sibling_node_index]
    # unmerged_leaves = sibling_node.parent_node ? sibling_node.parent_node.unmerged_leaves : []
    # unmerged_leaves = ratchet_tree[node_index].parent_node.unmerged_leaves
    # sibling_hash = MLS::Struct::RatchetTree.tree_hash_except(ratchet_tree, sibling_node_index, unmerged_leaves, suite)
    sibling_hash = MLS::Struct::RatchetTree.tree_hash(ratchet_tree, sibling_node_index, suite)
    calculated_parent_hash = MLS::Crypto.parent_hash(suite, encryption_key, calculated_parent_hash, sibling_hash)
    # p ratchet_tree[node_index]
    # puts "from: #{leaf_index_from}"
    # puts "node: #{node_index}"
    # puts "sibling: #{sibling_node_index}"
    # puts "sh: #{to_hex sibling_hash}"
    # puts "sh_w/o_unmerged: #{to_hex MLS::Struct::RatchetTree.tree_hash(ratchet_tree, sibling_node_index, suite)}"
    # puts "calc: #{to_hex calculated_parent_hash}"
  end

  update_path.leaf_node.parent_hash == calculated_parent_hash
end

# just a test function
def list_node_type(tree)
  tree.each_with_index do |node, index|
    if node.nil?
      puts "#{index}, nil"
    elsif node.parent_node
      puts "#{index}, PN"
    else
      puts "#{index}, LN"
    end
  end
end

vectors = JSON.load_file('test_vectors/treekem.json')[0..10]
vectors.each_with_index do |vector, tree_index|
  suite = MLS::Crypto::CipherSuite.new(vector['cipher_suite'])
  puts "for tree index #{tree_index}, cipher suite ID #{vector['cipher_suite']}:"

  confirmed_transcript_hash = from_hex(vector['confirmed_transcript_hash'])
  group_id = from_hex(vector['group_id'])
  epoch = vector['epoch']

  ratchet_tree = MLS::Struct::RatchetTree.parse(from_hex(vector['ratchet_tree']))

  private_treekem_state = []
  path_secrets = []

  # leaves_private
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
      path_secrets[ps['node']] = path_secret
    end
  end
  # Verify that the resulting private state leaf_private[i] is consistent with the ratchet_tree,
  # in the sense that for every node in the private state, the corresponding node in the tree is
  # (a) not blank and (b) contains the public key corresponding to the private key in the private state.
  assert_equal true, consistent?(private_treekem_state, ratchet_tree, suite)
  puts "[pass] Verify that the resulting private state leaf_private[i] is consistent with the ratchet_tree"

  # list_node_type ratchet_tree
  # update paths
  vector['update_paths'].each do |up|
    sender = up['sender']
    update_path = MLSStruct::UpdatePath.new(from_hex(up['update_path']))
    commit_secert = from_hex(up['commit_secret'])
    tree_hash_after = from_hex(up['tree_hash_after'])

    ## Verify that update_path is parent-hash valid relative to ratchet tree
    # update_path
    # puts "sender: #{sender}"
    assert_equal true, verify_parent_hash_of_path(suite, ratchet_tree, sender, update_path)
  end
  puts "[pass] Verify that update_path is parent-hash valid relative to ratchet tree"
end
