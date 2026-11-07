require 'json'
require 'melos'
require 'minitest'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

if ENV['TEST_ALL']
  vectors = JSON.load_file('test_vectors/passive-client-handling-commit.json')
else
  vectors = JSON.load_file('test_vectors/passive-client-handling-commit.json')[0..12]
end

vectors.each_with_index do |vec, vec_index|
  puts "vector # #{vec_index}, cipher suite #{vec['cipher_suite']}:"
  suite = Melos::Crypto::CipherSuite.new(vec['cipher_suite'])
  external_psks = vec['external_psks'].to_h { [from_hex(_1['psk_id']), from_hex(_1['psk'])] }
  # it says /* serialized KeyPackage */ but it's actually an MLSMessage that has a KeyPackage inside it!
  key_package = Melos::Struct::MLSMessage.new(from_hex(vec['key_package']))
  signature_priv = from_hex(vec['signature_priv'])
  encryption_priv = from_hex(vec['encryption_priv']) # the vector calls this leaf_priv
  init_priv = from_hex(vec['init_priv'])

  # Verify that signature_priv, leaf_priv, and init_priv correspond to the public keys (signature_key, encryption_key, and init_key) in the KeyPackage object described by key_package
  assert Melos::Crypto.signature_key_pair_corresponds?(suite, signature_priv, key_package.key_package.leaf_node.signature_key)
  assert Melos::Crypto.encapsulation_key_pair_corresponds?(suite, init_priv, key_package.key_package.init_key)
  assert Melos::Crypto.encapsulation_key_pair_corresponds?(suite, encryption_priv, key_package.key_package.leaf_node.encryption_key)
  puts "[pass] Verify that signature_priv, leaf_priv, and init_priv correspond to the public keys (signature_key, encryption_key, and init_key) in the KeyPackage object described by key_package"

  # Join the group using the Welcome message described by welcome, the ratchet tree described by ratchet_tree (if given) and the pre-shared keys described in external_psks
  group = Melos::Group.from_welcome(
    suite, Melos::Struct::MLSMessage.new(from_hex(vec['welcome'])),
    key_package: key_package,
    init_private_key: init_priv,
    encryption_private_key: encryption_priv,
    signature_private_key: signature_priv,
    external_psks: external_psks,
    ratchet_tree: vec['ratchet_tree'] && from_hex(vec['ratchet_tree'])
  )
  assert_equal from_hex(vec['initial_epoch_authenticator']), group.epoch_authenticator
  puts "[pass] Verify that the locally computed epoch_authenticator value is equal to the initial_epoch_authenticator value"

  # For each entry in epochs: process the proposals, then the commit, and compare the new epoch's authenticator
  vec['epochs'].each do |epoch_info|
    epoch_info['proposals'].each do |proposal|
      group.process_message(Melos::Struct::MLSMessage.new(from_hex(proposal)))
    end
    group.process_message(Melos::Struct::MLSMessage.new(from_hex(epoch_info['commit'])))
    assert_equal from_hex(epoch_info['epoch_authenticator']), group.epoch_authenticator
    puts "[pass] Verify that the locally computed epoch_authenticator value is equal to the epoch_authenticator value for epoch #{group.epoch}"
  end
end
