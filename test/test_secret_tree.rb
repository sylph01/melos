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
  secret_tree_vectors = JSON.parse(File.read('test_vectors/secret-tree.json'))
else
  secret_tree_vectors = JSON.parse(File.read('test_vectors/secret-tree.json'))[0..0]
end

secret_tree_vectors.each do |stv|
  suite = Melos::Crypto::CipherSuite.new(stv['cipher_suite'])
  n_leaves = stv['leaves'].count

  puts "for cipher suite ID #{stv['cipher_suite']}, n_leaves #{n_leaves}:"

  sender_data_secret = from_hex(stv['sender_data']['sender_data_secret'])
  ciphertext         = from_hex(stv['sender_data']['ciphertext'])

  sender_data_key   = Melos::Crypto.sender_data_key(suite, sender_data_secret, ciphertext)
  sender_data_nonce = Melos::Crypto.sender_data_nonce(suite, sender_data_secret, ciphertext)
  assert_equal to_hex(sender_data_key), stv['sender_data']['key']
  puts '[s] key == sender_data_key(sender_data_secret, ciphertext)'
  assert_equal to_hex(sender_data_nonce), stv['sender_data']['nonce']
  puts '[s] nonce == sender_data_nonce(sender_data_secret, ciphertext)'

  encryption_secret = from_hex(stv['encryption_secret'])
  ## Initialize a secret tree with a number of leaves equal to the number of entries in the leaves array
  secret_tree = Melos::SecretTree.new(suite, n_leaves, encryption_secret)

  stv['leaves'].each_with_index do |array, leaf_index|
    puts "for leaf index #{leaf_index}:"
    array.each do |gen|
      ## For each entry in the array: derive the handshake and application keys and nonces for the given generation
      handshake_key, handshake_nonce, = secret_tree.ratchet_until_and_get(Melos::Constants::ContentType::PROPOSAL, leaf_index, gen['generation'])
      application_key, application_nonce, = secret_tree.ratchet_until_and_get(Melos::Constants::ContentType::APPLICATION, leaf_index, gen['generation'])
      assert_equal gen['handshake_key'], to_hex(handshake_key)
      assert_equal gen['handshake_nonce'], to_hex(handshake_nonce)
      assert_equal gen['application_key'], to_hex(application_key)
      assert_equal gen['application_nonce'], to_hex(application_nonce)
      puts "[s] at generation #{gen['generation']}, handshake_(key/nonce), application_(key/nonce) matches"
    end
  end
end
