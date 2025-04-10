require 'json'
require 'melos'
require 'minitest'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

# test all anyways
welcome_vectors = JSON.parse(File.read('test_vectors/welcome.json'))

welcome_vectors.each do |wv|
  suite = Melos::Crypto::CipherSuite.new(wv['cipher_suite'])
  puts "cipher suite #{wv['cipher_suite']}:"

  init_priv_raw  = from_hex(wv['init_priv'])
  signer_pub_raw = from_hex(wv['signer_pub'])

  welcome = Melos::Struct::MLSMessage.new(from_hex(wv['welcome']))
  key_package = Melos::Struct::MLSMessage.new(from_hex(wv['key_package']))

  ## Identify the entry in welcome.secrets corresponding to key_package
  key_package_ref = key_package.key_package.ref(suite)
  encrypted_group_secrets = welcome.welcome.secrets.find { _1.new_member == key_package_ref }&.encrypted_group_secrets

  if encrypted_group_secrets.nil?
    puts "[f] Encrypted Group Secrets corresponding to key package reference is not found in Welcome message"
    exit 1
  end
  puts "[s] Identify the entry in welcome.secrets corresponding to key_package"

  ## Decrypt the encrypted group secrets using init_priv
  encrypted_group_info = welcome.welcome.encrypted_group_info
  decrypted_group_secrets = Melos::Crypto.decrypt_with_label(
    suite,
    init_priv_raw,
    "Welcome",
    encrypted_group_info,
    encrypted_group_secrets.kem_output,
    encrypted_group_secrets.ciphertext
  )
  group_secrets = Melos::Struct::GroupSecrets.new(decrypted_group_secrets)
  puts "[s] Decrypt the encrypted group secrets using init_priv"

  ## Decrypt the encrypted group info
  joiner_secret = group_secrets.joiner_secret
  ## TODO: make key schedule into a module
  # note that this is possible because PSKs are empty. We need to calculate psk_secret if psks are present
  psk_secret = Melos::Crypto::Util.zero_vector(suite.kdf.n_h)
  member_secret = Melos::Crypto.kdf_extract(suite, joiner_secret, psk_secret)
  welcome_secret = Melos::Crypto.derive_secret(suite, member_secret, "welcome")
  welcome_nonce = Melos::Crypto.expand_with_label(suite, welcome_secret, "nonce", "", suite.hpke.n_n)
  welcome_key   = Melos::Crypto.expand_with_label(suite, welcome_secret, "key",   "", suite.hpke.n_k)
  decrypted_group_info = Melos::Crypto.aead_decrypt(
    suite,
    welcome_key,
    welcome_nonce,
    "",
    encrypted_group_info
  )
  group_info = Melos::Struct::GroupInfo.new(decrypted_group_info)
  puts "[s] Decrypt the encrypted group info"

  ## Verify the signature on the decrypted group info using signer_pub
  ## known issue: this fails on cipher suite 5 and 7
  assert_equal group_info.verify(suite, signer_pub_raw), true
  puts "[s] Verify the signature on the decrypted group info using signer_pub"

  ## Initialize a key schedule epoch using the decrypted joiner_secret and no PSKs
  epoch_secret = Melos::Crypto.expand_with_label(suite, member_secret, "epoch", group_info.group_context.raw, suite.kdf.n_h)
  confirmation_key = Melos::Crypto.derive_secret(suite, epoch_secret, 'confirm')

  ## Recompute a candidate confirmation_tag value using the confirmation_key from the key schedule epoch and the confirmed_transcript_hash from the decrypted GroupContext
  assert_equal group_info.confirmation_tag, Melos::Crypto.mac(suite, confirmation_key, group_info.group_context.confirmed_transcript_hash)
  puts "[s] Recompute a candidate confirmation_tag value using the confirmation_key from the key schedule epoch and the confirmed_transcript_hash from the decrypted GroupContext"
end
