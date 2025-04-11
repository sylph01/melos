require 'json'
require 'melos'
require 'minitest'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

vectors = JSON.load_file('test_vectors/passive-client-welcome.json')

vectors.each_with_index do |vec, vec_index|
  puts "vector # #{vec_index}:"
  suite = Melos::Crypto::CipherSuite.new(vec['cipher_suite'])
  # As reading from bc-java's implementation, this test assumes that psk_nonce is the psk itself...?
  external_psks = vec['external_psks'].map {
    [from_hex(_1['psk_id']), from_hex(_1['psk'])]
  }.to_h
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

  # 12.4.3.1 Joining via Welcome Message
  # Join the group using the Welcome message described by welcome, the ratchet tree described by ratchet_tree (if given) and the pre-shared keys described in external_psks
  # param: welcome message itself, keypackage, external_psks(psk_id_name -> psk)
  kp_ref = key_package.key_package.ref(suite)
  # identify which new_member entry to use
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
  psk_ids = group_secrets.psks
  psks = psk_ids.map do |psk_id|
    {
      psk_id: psk_id.raw,
      psk: external_psks[psk_id.psk_id]
    }
  end
  # TODO: If a PreSharedKeyID is part of the GroupSecrets and the client is not in possession of the corresponding PSK, return an error. Additionally, if a PreSharedKeyID has type resumption with usage reinit or branch, verify that it is the only such PSK.
  psk_secret = Melos::PSK.psk_secret(suite, psks)

  key, nonce = Melos::KeySchedule.welcome_key_and_nonce(suite, joiner_secret, psk_secret)
  group_info = Melos::Struct::GroupInfo.new(
    Melos::Crypto.aead_decrypt(
      suite,
      key,
      nonce,
      "",
      welcome.welcome.encrypted_group_info
    )
  )

  ## verify signature of GroupInfo object
  group_info_signer = group_info.signer
  # construct ratchet tree
  if vec['ratchet_tree']
    # get ratchet tree from vector
    ratchet_tree = Melos::Struct::RatchetTree.parse(from_hex(vec['ratchet_tree']))
  else
    # get ratchet tree from extensions
    ratchet_tree = Melos::Struct::RatchetTree.parse(group_info.extensions.find { _1.extension_type == Melos::Constants::ExtensionType::RATCHET_TREE }.extension_data)
  end
  # get signer key
  pub_key_of_signer = ratchet_tree[group_info_signer * 2].leaf_node.signature_key
  assert group_info.verify(suite, pub_key_of_signer)

  group_context = group_info.group_context
  # we want this out of processing welcome

  epoch_secret = Melos::KeySchedule.epoch_secret(suite, joiner_secret, psk_secret, group_context)
  epoch_authenticator = Melos::KeySchedule.epoch_authenticator(suite, epoch_secret)
  assert_equal epoch_authenticator, from_hex(vec['initial_epoch_authenticator'])
  puts "[pass] Verify that the locally computed epoch_authenticator value is equal to the initial_epoch_authenticator value"
end
