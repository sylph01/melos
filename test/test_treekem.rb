require 'json'
require 'minitest'
require 'mls'
include Minitest::Assertions
include MLS::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

# TODO: move to PrivateTree class
def consistent?(private_tree, public_tree, suite)
  # private tree contains mappings of (node -> private key)
  result = true
  private_tree.each_with_index do |private_node, private_node_index|
    if !private_node.nil?
      public_node = public_tree[private_node_index]
      result = false and next if public_node.nil?
      # check if private key corresponds to public key
      resulf = false and next if !MLS::Crypto.encapsulation_key_pair_corresponds?(suite, private_node, public_node.public_encryption_key)
    end
  end
  result
end

# maybe in RatchetTree class?
def verify_parent_hash_of_path(suite, ratchet_tree, leaf_index_from, update_path)
  calculated_parent_hash = MLS::Struct::RatchetTree.calculate_parent_hashes(suite, ratchet_tree, leaf_index_from, update_path.nodes)[0]
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

vectors = JSON.load_file('test_vectors/treekem.json')
vectors.each_with_index do |vector, tree_index|
  suite = MLS::Crypto::CipherSuite.new(vector['cipher_suite'])
  puts "for tree index #{tree_index}, cipher suite ID #{vector['cipher_suite']}:"

  confirmed_transcript_hash = from_hex(vector['confirmed_transcript_hash'])
  group_id = from_hex(vector['group_id'])
  epoch = vector['epoch']

  ratchet_tree = MLS::Struct::RatchetTree.parse(from_hex(vector['ratchet_tree']))

  encryption_priv_tree = []
  signature_priv_tree = []
  path_secrets = []

  # leaves_private
  vector['leaves_private'].each do |leaf_private|
    leaf_index = leaf_private['index']
    node_index_of_leaf = leaf_index * 2
    encryption_priv = from_hex(leaf_private['encryption_priv']) # HPKE private key
    signature_priv  = from_hex(leaf_private['signature_priv'])  # signature private key
    # Associate encryption_priv and signature_priv with the leaf node
    encryption_priv_tree[node_index_of_leaf] = encryption_priv
    signature_priv_tree[node_index_of_leaf]  = signature_priv
    # For each entry in path_secrets:
    leaf_private['path_secrets'].each do |ps|
      ## Identify the node in the tree with node index node in the array representation of the tree
      public_node = ratchet_tree[ps['node']]
      ## Set the private value at this node based on path_secret
      path_secret = from_hex(ps['path_secret'])
      path_secrets[ps['node']] = path_secret
      encryption_priv, encryption_pub = MLS::Crypto.derive_key_pair(suite, MLS::Crypto.derive_secret(suite, path_secret, "node"))
      encryption_priv_tree[ps['node']] = encryption_priv
    end
  end
  # Verify that the resulting private state leaf_private[i] is consistent with the ratchet_tree,
  # in the sense that for every node in the private state, the corresponding node in the tree is
  # (a) not blank and (b) contains the public key corresponding to the private key in the private state.
  assert_equal true, consistent?(encryption_priv_tree, ratchet_tree, suite)
  puts "[pass] Verify that the resulting private state leaf_private[i] is consistent with the ratchet_tree"

  # update paths
  vector['update_paths'].each do |up|
    sender = up['sender']
    puts "For sender #{sender} (node: #{sender * 2})"
    update_path = MLS::Struct::UpdatePath.new(from_hex(up['update_path']))
    commit_secret = from_hex(up['commit_secret'])
    tree_hash_after = from_hex(up['tree_hash_after'])

    ## Verify that update_path is parent-hash valid relative to ratchet tree
    # puts "sender: #{sender}"
    assert_equal true, verify_parent_hash_of_path(suite, ratchet_tree, sender, update_path)
    puts "[pass] Verify that update_path is parent-hash valid relative to ratchet tree"

    # Compute the ratchet tree that results from merging update_path into ratchet_tree, and verify that its root tree hash is equal to .tree_hash_after
    new_tree = MLS::Struct::RatchetTree.parse(from_hex(vector['ratchet_tree']))
    MLS::Struct::RatchetTree.merge_update_path(suite, new_tree, sender, update_path)
    assert_equal tree_hash_after, MLS::Struct::RatchetTree.root_tree_hash(suite, new_tree)
    puts "[pass] Compute the ratchet tree that results from merging update_path into ratchet_tree, and verify that its root tree hash is equal to .tree_hash_after"

    group_context = MLS::Struct::GroupContext.create(
      cipher_suite: vector['cipher_suite'],
      group_id: group_id,
      epoch: epoch,
      tree_hash: MLS::Struct::RatchetTree.root_tree_hash(suite, new_tree),
      confirmed_transcript_hash: confirmed_transcript_hash,
      extensions: []
    )

    # puts "fdp: #{MLS::Tree.filtered_direct_path(new_tree, sender)}"
    # puts "copath_nodes: #{MLS::Tree.copath_nodes_of_filtered_direct_path(new_tree, sender)}"
    # p MLS::Tree.copath_nodes_of_filtered_direct_path(new_tree, sender).map { MLS::Tree.resolution(new_tree, _1) }
    # pp update_path.nodes.map{ _1.encrypted_path_secret.count }
    # pp encryption_priv_tree
    up['path_secrets'].each_with_index do |path_secret, j_index|
      next if sender == j_index
      puts "receiver: #{j_index} (node: #{j_index * 2})"
      if path_secret
        decrypted_path_secret = MLS::Struct::RatchetTree.decrypt_path_secret(suite, new_tree, encryption_priv_tree, update_path, sender, j_index, group_context)
        assert_equal decrypted_path_secret, from_hex(path_secret)
        puts "[pass] Verify that path_secrets[j] is the decrypted path secret"
        calculated_commit_secret = MLS::Struct::RatchetTree.calculate_commit_secret(suite, new_tree, update_path, sender, j_index, decrypted_path_secret)
        assert_equal commit_secret, calculated_commit_secret
        puts "[pass] Verify that commit_secret is the resulting commit secret"
      else
        puts "[pass] Verify that path_secrets[j] is the decrypted path secret (no path secret here)"
      end
    end

    ## create a new updatePath
    ## TODO: move this to RatchetTree
    leaf_node_options = [] # credential, capabilities, extensions; bc-java thing?
    another_new_tree = ratchet_tree.dup
    original_leaf_node = another_new_tree[sender * 2]
    leaf_secret = MLS::Crypto::Util.zero_vector(suite.kdf.n_h) # actually make it with a random value
    fdp = MLS::Tree.filtered_direct_path(another_new_tree, sender)
    path_secrets = []
    current_path_secret = leaf_secret
    fdp.each do
      current_path_secret = MLS::Crypto.derive_secret(suite, current_path_secret, "path")
      path_secrets << current_path_secret
    end
    new_commit_secret = MLS::Crypto.derive_secret(suite, current_path_secret, "path")
    update_path_nodes = []
    fdp.each_with_index do |fdp_node_index, array_index|
      path_secret = path_secrets[array_index]
      node_private_key, node_public_key = MLS::Crypto.derive_key_pair(suite, MLS::Crypto.derive_secret(suite, path_secret, "node"))

      update_path_node = MLS::Struct::UpdatePathNode.create(
        encryption_key: node_public_key,
        encrypted_path_secret: []
      )
      update_path_nodes << update_path_node
    end
    parent_hashes = MLS::Struct::RatchetTree.calculate_parent_hashes(suite, another_new_tree, sender, update_path_nodes)
    ph0 = parent_hashes.count == 0 ? "" : parent_hashes[0]
    leaf_private_key, leaf_public_key = MLS::Crypto.derive_key_pair(suite, MLS::Crypto.derive_secret(suite, leaf_secret, "node"))
    # create new leaf node to replace sender
    new_leaf_node = MLS::Struct::LeafNode.create(
      encryption_key: leaf_public_key,
      signature_key: original_leaf_node.leaf_node.signature_key,
      credential: original_leaf_node.leaf_node.credential,
      capabilities: original_leaf_node.leaf_node.capabilities,
      leaf_node_source: 0x03, # commit
      lifetime: original_leaf_node.leaf_node.lifetime,
      parent_hash: ph0,
      extensions: original_leaf_node.leaf_node.extensions,
      signature: nil
    )
    new_leaf_node.sign(suite, signature_priv_tree[sender * 2], group_id, sender)
    update_path = MLS::Struct::UpdatePath.create(
      leaf_node: new_leaf_node,
      nodes: update_path_nodes
    )
    # apply update path to self
    MLS::Struct::RatchetTree.merge_update_path(suite, another_new_tree, sender, update_path)

    except = [] # TODO: unused for now, use this to remove leaves from resolution
    copath_nodes = MLS::Tree.copath_nodes_of_filtered_direct_path(another_new_tree, sender)
    update_path_nodes = []
    fdp.each_with_index do |fdp_node_index, array_index|
      copath_node_index = copath_nodes[array_index]
      copath_node_resolution = MLS::Tree.resolution(another_new_tree, copath_node_index)

      path_secret = path_secrets[array_index]
      node_private_key, node_public_key = MLS::Crypto.derive_key_pair(suite, MLS::Crypto.derive_secret(suite, path_secret, "node"))

      ciphertexts = []
      copath_node_resolution.each do |resolution_node_index|
        resolution_node_public_key = another_new_tree[resolution_node_index].public_encryption_key

        # check that encryption_priv_tree has the private key that corresponds to this resolution node public key
        assert_equal true, MLS::Crypto.encapsulation_key_pair_corresponds?(suite, encryption_priv_tree[resolution_node_index], resolution_node_public_key)

        kem_output, ciphertext = MLS::Crypto.encrypt_with_label(suite, resolution_node_public_key, "UpdatePathNode", group_context.raw, path_secret)
        hpke_ciphertext = MLS::Struct::HPKECipherText.create(
          kem_output: kem_output,
          ciphertext: ciphertext
        )
        ciphertexts << hpke_ciphertext
      end
      update_path_node = MLS::Struct::UpdatePathNode.create(
        encryption_key: node_public_key,
        encrypted_path_secret: ciphertexts
      )
      update_path_nodes << update_path_node
    end
    new_update_path = MLS::Struct::UpdatePath.create(
      leaf_node: another_new_tree[sender * 2].leaf_node,
      nodes: update_path_nodes
    )
    # then verify parent hash of new path
    assert_equal true, verify_parent_hash_of_path(suite, another_new_tree, sender, new_update_path)

    # then assert that decapsulation succeeds from each leaf on this update path
    (0..(MLS::Tree.n_leaves(another_new_tree) - 1)).each do |leaf_index|
      next if leaf_index == sender
      puts "With new update path, sender #{sender}, receiver #{leaf_index}:"
      decrypted_path_secret = MLS::Struct::RatchetTree.decrypt_path_secret(suite, another_new_tree, encryption_priv_tree, new_update_path, sender, leaf_index, group_context)
      calculated_commit_secret = MLS::Struct::RatchetTree.calculate_commit_secret(suite, another_new_tree, new_update_path, sender, leaf_index, decrypted_path_secret)
      assert_equal new_commit_secret, calculated_commit_secret
      puts "[pass] Verify that commit_secret is the resulting commit secret"
    end
  end

end
