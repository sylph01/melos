require 'json'
require 'minitest'
require_relative 'tree'
require_relative 'crypto'
require_relative 'vec_base'
require_relative 'secret_tree'
include Minitest::Assertions

class << self
attr_accessor :assertions
end
self.assertions = 0

secret_tree_vectors = JSON.parse(File.read('test_vectors/secret-tree.json'))

secret_tree_vectors.each do |stv|
  suite = MLS::Crypto::CipherSuite.new(stv['cipher_suite'])
  n_leaves = stv['leaves'].count

  puts "for cipher suite ID #{stv['cipher_suite']}, n_leaves #{n_leaves}:"

  sender_data_secret = from_hex(stv['sender_data']['sender_data_secret'])
  ciphertext         = from_hex(stv['sender_data']['ciphertext'])

  sender_data_key   = MLS::SecretTree.sender_data_key(suite, sender_data_secret, ciphertext)
  sender_data_nonce = MLS::SecretTree.sender_data_nonce(suite, sender_data_secret, ciphertext)
  assert_equal to_hex(sender_data_key), stv['sender_data']['key']
  puts '[s] key == sender_data_key(sender_data_secret, ciphertext)'
  assert_equal to_hex(sender_data_nonce), stv['sender_data']['nonce']
  puts '[s] nonce == sender_data_nonce(sender_data_secret, ciphertext)'

  encryption_secret = from_hex(stv['encryption_secret'])
  ## Initialize a secret tree with a number of leaves equal to the number of entries in the leaves array
  secret_tree = MLS::Tree.empty_tree(n_leaves)
  ## with encryption_secret as the root secret
  MLS::SecretTree.populate_tree(suite, secret_tree, encryption_secret)

  # p secret_tree.array
  stv['leaves'].each_with_index do |array, leaf_index|
    # assumes that generation only goes up till 15
    puts "for leaf index #{leaf_index}:"
    (0..15).each do |gen_num|
      MLS::SecretTree.ratchet(suite, secret_tree, leaf_index)
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
