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
  vectors = JSON.load_file('test_vectors/treekem.json')
else
  vectors = JSON.load_file('test_vectors/treekem.json').select { _1['cipher_suite'] == 1 }
end

vectors.each_with_index do |vector, tree_index|
  suite = Melos::Crypto::CipherSuite.new(vector['cipher_suite'])
  puts "for tree index #{tree_index}, cipher suite ID #{vector['cipher_suite']}:"

  confirmed_transcript_hash = from_hex(vector['confirmed_transcript_hash'])
  group_id = from_hex(vector['group_id'])
  epoch = vector['epoch']

  ratchet_tree = Melos::RatchetTree.parse(suite, from_hex(vector['ratchet_tree']))

  # The vector gives the private state of every leaf at once, so this one PrivateTree
  # stands in for all members; a real member only ever holds its own.
  private_tree = Melos::PrivateTree.new
  signature_privs = {} # leaf index -> signature private key

  vector['leaves_private'].each do |leaf_private|
    leaf_index = leaf_private['index']
    # Associate encryption_priv and signature_priv with the leaf node
    private_tree[leaf_index * 2] = from_hex(leaf_private['encryption_priv'])
    signature_privs[leaf_index] = from_hex(leaf_private['signature_priv'])
    # For each entry in path_secrets, set the private value at node based on path_secret
    leaf_private['path_secrets'].each do |ps|
      path_secret = from_hex(ps['path_secret'])
      private_key, _public_key = Melos::Crypto.derive_key_pair(suite, Melos::Crypto.derive_secret(suite, path_secret, "node"))
      private_tree[ps['node']] = private_key
    end
  end
  # Verify that the resulting private state leaf_private[i] is consistent with the ratchet_tree,
  # in the sense that for every node in the private state, the corresponding node in the tree is
  # (a) not blank and (b) contains the public key corresponding to the private key in the private state.
  assert_equal true, private_tree.consistent?(ratchet_tree)
  puts "[pass] Verify that the resulting private state leaf_private[i] is consistent with the ratchet_tree"

  vector['update_paths'].each do |up|
    sender = up['sender']
    puts "For sender #{sender} (node: #{sender * 2})"
    update_path = Melos::Struct::UpdatePath.new(from_hex(up['update_path']))
    commit_secret = from_hex(up['commit_secret'])

    ## Verify that update_path is parent-hash valid relative to ratchet tree
    assert_equal true, ratchet_tree.verify_parent_hash_of_path(sender, update_path)
    puts "[pass] Verify that update_path is parent-hash valid relative to ratchet tree"

    ## Compute the ratchet tree that results from merging update_path into ratchet_tree, and verify that its root tree hash is equal to tree_hash_after
    new_tree = ratchet_tree.dup
    new_tree.merge_update_path(sender, update_path)
    assert_equal from_hex(up['tree_hash_after']), new_tree.root_tree_hash
    puts "[pass] Compute the ratchet tree that results from merging update_path into ratchet_tree, and verify that its root tree hash is equal to .tree_hash_after"

    group_context = Melos::Struct::GroupContext.create(
      cipher_suite: vector['cipher_suite'],
      group_id: group_id,
      epoch: epoch,
      tree_hash: new_tree.root_tree_hash,
      confirmed_transcript_hash: confirmed_transcript_hash,
      extensions: []
    )

    ## For each leaf j != sender, decrypt the path secret and derive the commit secret
    up['path_secrets'].each_with_index do |path_secret, j_index|
      next if sender == j_index
      puts "receiver: #{j_index} (node: #{j_index * 2})"
      if path_secret
        receiver_private_tree = private_tree.dup
        decrypted_path_secret = new_tree.decrypt_path_secret(receiver_private_tree, update_path, sender, j_index, group_context)
        assert_equal from_hex(path_secret), decrypted_path_secret
        puts "[pass] Verify that path_secrets[j] is the decrypted path secret"
        assert_equal commit_secret, new_tree.calculate_commit_secret(update_path, sender, j_index, decrypted_path_secret)
        puts "[pass] Verify that commit_secret is the resulting commit secret"
      else
        puts "[pass] Verify that path_secrets[j] is the decrypted path secret (no path secret here)"
      end
    end

    ## Create a new UpdatePath from the sender, then verify it from every other leaf
    sender_private_tree = private_tree.dup
    # create_update_path replaces the tree hash in the given GroupContext with that of the tree after the merge
    result = ratchet_tree.create_update_path(sender_private_tree, sender, signature_privs[sender], group_context)

    another_new_tree = ratchet_tree.dup
    another_new_tree.merge_update_path(sender, result[:update_path])
    provisional_group_context = Melos::Struct::GroupContext.create(
      cipher_suite: vector['cipher_suite'],
      group_id: group_id,
      epoch: epoch,
      tree_hash: another_new_tree.root_tree_hash,
      confirmed_transcript_hash: confirmed_transcript_hash,
      extensions: []
    )
    assert_equal true, another_new_tree.verify_parent_hash_of_path(sender, result[:update_path])
    puts "[pass] New update path is parent-hash valid relative to the tree it was merged into"
    # create_update_path wrote the sender's new leaf and path private keys into its private tree
    assert_equal true, sender_private_tree.consistent?(another_new_tree)
    puts "[pass] Sender's private tree is consistent with the merged tree"

    another_new_tree.each_leaf_node do |_leaf_node, leaf_index|
      next if leaf_index == sender
      puts "With new update path, sender #{sender}, receiver #{leaf_index}:"
      receiver_private_tree = private_tree.dup
      decrypted_path_secret = another_new_tree.decrypt_path_secret(receiver_private_tree, result[:update_path], sender, leaf_index, provisional_group_context)
      assert_equal result[:commit_secret], another_new_tree.calculate_commit_secret(result[:update_path], sender, leaf_index, decrypted_path_secret)
      puts "[pass] Verify that commit_secret is the resulting commit secret"
    end
  end
end
