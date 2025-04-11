require 'json'
require 'melos'
require 'minitest'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

vectors = JSON.load_file('test_vectors/passive-client-welcome.json')[0..0]

vectors.each do |vec|
  suite = Melos::Crypto::CipherSuite.new(vec['cipher_suite'])
  external_psks = vec['external_psks'].map {
    {
      psk_id: from_hex(_1['psk_id']),
      psk: from_hex(_1['psk'])
    }
  }
  # it says /* serialized KeyPackage */ but it's actually an MLSMessage that has a KeyPackage inside it!
  key_package = Melos::Struct::MLSMessage.new(from_hex(vec['key_package']))
  signature_priv = from_hex(vec['signature_priv'])
  encryption_priv = from_hex(vec['encryption_priv']) # hello what is a `leaf_priv`?
  init_priv = from_hex(vec['init_priv'])

  # Verify that signature_priv, leaf_priv, and init_priv correspond to the public keys (signature_key, encryption_key, and init_key) in the KeyPackage object described by key_package
  init_pub_from_keypackage = key_package.key_package.init_key
  signature_pub_from_keypackage = key_package.key_package.leaf_node.signature_key
  encryption_pub_from_key_package = key_package.key_package.leaf_node.encryption_key

  assert Melos::Crypto.signature_key_pair_corresponds?(suite, signature_priv, signature_pub_from_keypackage)
  assert Melos::Crypto.encapsulation_key_pair_corresponds?(suite, init_priv, init_pub_from_keypackage)
  assert Melos::Crypto.encapsulation_key_pair_corresponds?(suite, encryption_priv, encryption_pub_from_key_package)
  puts "[pass] Verify that signature_priv, leaf_priv, and init_priv correspond to the public keys (signature_key, encryption_key, and init_key) in the KeyPackage object described by key_package"

  welcome = Melos::Struct::MLSMessage.new(from_hex(vec['welcome']))

  # process welcome
  # param: welcome message itself, keypackage, psks
  kp_ref = key_package.key_package.ref(suite)
  egs = welcome.welcome.secrets.find { _1.new_member == kp_ref }&.encrypted_group_secrets

  group_secrets = Melos::Struct::GroupSecrets.new(
    Melos::Crypto.decrypt_with_label(
      suite,
      init_priv,
      "Welcome",
      welcome.welcome.encrypted_group_info,
      egs.kem_output,
      egs.ciphertext
    )
  )
  joiner_secret = group_secrets.joiner_secret
  p group_secrets
end
