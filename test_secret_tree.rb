require 'json'
require 'minitest'
require_relative 'tree'
require_relative 'crypto'
require_relative 'vec_base'
include Minitest::Assertions

class << self
attr_accessor :assertions
end
self.assertions = 0

secret_tree_vectors = JSON.parse(File.read('test_vectors/secret-tree.json'))

module SecretTree
  def self.sender_data_key(suite, sender_data_secret, ciphertext)
    ciphertext_sample = ciphertext[0..(suite.kdf.n_h - 1)]
    MLS::Crypto.expand_with_label(suite, sender_data_secret, "key", ciphertext_sample, suite.hpke.n_k)
  end

  def self.sender_data_nonce(suite, sender_data_secret, ciphertext)
    ciphertext_sample = ciphertext[0..(suite.kdf.n_h - 1)]
    MLS::Crypto.expand_with_label(suite, sender_data_secret, "nonce", ciphertext_sample, suite.hpke.n_n)
  end

  def self.populate_tree(suite, tree, root_secret)
    populate_tree_impl(suite, tree, tree.root, root_secret)
  end

  def self.populate_tree_impl(suite, tree, index, secret)
    tree.array[index] = {'tree_node_secret' => secret, 'ratchet_secret_generation' => 0}
    unless MLS::Tree.leaf?(index)
      left_secret  = MLS::Crypto.expand_with_label(suite, secret, "tree", "left", suite.kdf.n_h)
      right_secret = MLS::Crypto.expand_with_label(suite, secret, "tree", "right", suite.kdf.n_h)
      populate_tree_impl(suite, tree, MLS::Tree.left(index), left_secret)
      populate_tree_impl(suite, tree, MLS::Tree.right(index), right_secret)
    end
  end

  def self.ratchet(suite, tree, leaf_index)
    node_index = leaf_index * 2
    tree_node_secret = tree.array[node_index]['tree_node_secret']
    generation = tree.array[node_index]['ratchet_secret_generation']
    if generation == 0
      handshake_ratchet_secret   = MLS::Crypto.expand_with_label(suite, tree_node_secret, "handshake",   "", suite.kdf.n_h)
      application_ratchet_secret = MLS::Crypto.expand_with_label(suite, tree_node_secret, "application", "", suite.kdf.n_h)
    else
      handshake_ratchet_secret = tree.array[node_index]['handshake_ratchet_secret']
      application_ratchet_secret = tree.array[node_index]['application_ratchet_secret']
    end
    handshake_nonce = MLS::Crypto.derive_tree_secret(suite, handshake_ratchet_secret, "nonce", generation, suite.hpke.n_n)
    handshake_key   = MLS::Crypto.derive_tree_secret(suite, handshake_ratchet_secret, "key",   generation, suite.hpke.n_k)
    application_nonce = MLS::Crypto.derive_tree_secret(suite, application_ratchet_secret, "nonce", generation, suite.hpke.n_n)
    application_key   = MLS::Crypto.derive_tree_secret(suite, application_ratchet_secret, "key",   generation, suite.hpke.n_k)

    next_handshake_ratchet_secret   = MLS::Crypto.derive_tree_secret(suite, handshake_ratchet_secret, "secret", generation, suite.kdf.n_h)
    next_application_ratchet_secret = MLS::Crypto.derive_tree_secret(suite, application_ratchet_secret, "secret", generation, suite.kdf.n_h)
    tree.array[node_index] = {
      'ratchet_secret_generation' => generation + 1,
      'handshake_nonce' => handshake_nonce,
      'handshake_key' => handshake_key,
      'handshake_ratchet_secret' => next_handshake_ratchet_secret,
      'application_nonce' => application_nonce,
      'application_key' => application_key,
      'application_ratchet_secret' => next_application_ratchet_secret
    }
  end
end


secret_tree_vectors.each do |stv|
  suite = MLS::Crypto::CipherSuite.new(stv['cipher_suite'])
  n_leaves = stv['leaves'].count

  puts "for cipher suite ID #{stv['cipher_suite']}, n_leaves #{n_leaves}:"

  sender_data_secret = from_hex(stv['sender_data']['sender_data_secret'])
  ciphertext         = from_hex(stv['sender_data']['ciphertext'])

  sender_data_key   = SecretTree.sender_data_key(suite, sender_data_secret, ciphertext)
  sender_data_nonce = SecretTree.sender_data_nonce(suite, sender_data_secret, ciphertext)
  assert_equal to_hex(sender_data_key), stv['sender_data']['key']
  puts '[s] key == sender_data_key(sender_data_secret, ciphertext)'
  assert_equal to_hex(sender_data_nonce), stv['sender_data']['nonce']
  puts '[s] nonce == sender_data_nonce(sender_data_secret, ciphertext)'

  encryption_secret = from_hex(stv['encryption_secret'])
  ## Initialize a secret tree with a number of leaves equal to the number of entries in the leaves array
  secret_tree = MLS::Tree.empty_tree(n_leaves)
  ## with encryption_secret as the root secret
  SecretTree.populate_tree(suite, secret_tree, encryption_secret)

  # p secret_tree.array
  stv['leaves'].each_with_index do |array, leaf_index|
    # assumes that generation only goes up till 15
    puts "for leaf index #{leaf_index}:"
    (0..15).each do |gen_num|
      SecretTree.ratchet(suite, secret_tree, leaf_index)
      # check if there is a generation that matches
      generation = array.find { _1['generation'] == gen_num}
      if !generation.nil?
        assert_equal to_hex(secret_tree.leaf_at(leaf_index)['handshake_key']), generation['handshake_key']
        assert_equal to_hex(secret_tree.leaf_at(leaf_index)['handshake_nonce']), generation['handshake_nonce']
        assert_equal to_hex(secret_tree.leaf_at(leaf_index)['application_key']), generation['application_key']
        assert_equal to_hex(secret_tree.leaf_at(leaf_index)['application_nonce']), generation['application_nonce']
        puts "[s] at generation #{generation['generation']}, handshake_(key/nonce), application_(key/nonce) matches"
      end
    end
  end
end
