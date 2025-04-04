require 'json'
require_relative 'crypto'
require_relative 'vec_base'
require_relative 'structs'
require 'minitest'
include Minitest::Assertions

class << self
attr_accessor :assertions
end
self.assertions = 0

welcome_vectors = JSON.parse(File.read('test_vectors/welcome.json')).select { _1['cipher_suite'] == 1}

welcome_vectors.each do |wv|
  init_priv_raw  = from_hex(wv['init_priv'])
  signer_pub_raw = from_hex(wv['signer_pub'])

  welcome = MLSStruct::MLSMessage.new(from_hex(wv['welcome']))
  key_package = MLSStruct::MLSMessage.new(from_hex(wv['key_package']))

  ## Identify the entry in welcome.secrets corresponding to key_package
  encrypted_group_secrets = welcome.welcome.secrets.first.encrypted_group_secrets

  ## Decrypt the encrypted group secrets using init_priv
  encrypted_group_info = welcome.welcome.encrypted_group_info
  decrypted_group_secrets = MLS::Crypto.decrypt_with_label(
    init_priv_raw,
    "Welcome",
    encrypted_group_info,
    encrypted_group_secrets.kem_output,
    encrypted_group_secrets.ciphertext
  )
  group_secrets = MLSStruct::GroupSecrets.new(decrypted_group_secrets)
  puts "[s] Decrypt the encrypted group secrets using init_priv"

  ## Decrypt the encrypted group info
  joiner_secret = group_secrets.joiner_secret
  ## TODO: make key schedule into a module
  # note that this is possible because PSKs are empty. We need to calculate psk_secret if psks are present
  psk_secret = MLS::Crypto.zero_vector(MLS::Crypto.kdf_n_h)
  member_secret = MLS::Crypto.kdf_extract(joiner_secret, psk_secret)
  welcome_secret = MLS::Crypto.derive_secret(member_secret, "welcome")
  welcome_nonce = MLS::Crypto.expand_with_label(welcome_secret, "nonce", "", MLS::Crypto.aead_n_n)
  welcome_key   = MLS::Crypto.expand_with_label(welcome_secret, "key",   "", MLS::Crypto.aead_n_k)
  decrypted_group_info = MLS::Crypto.aead_decrypt(
    welcome_key,
    welcome_nonce,
    "",
    encrypted_group_info
  )
  group_info = MLSStruct::GroupInfo.new(decrypted_group_info)
  puts "[s] Decrypt the encrypted group info"

  ## Verify the signature on the decrypted group info using signer_pub
  assert_equal group_info.verify(signer_pub_raw), true
  puts "[s] Verify the signature on the decrypted group info using signer_pub"

  ## Initialize a key schedule epoch using the decrypted joiner_secret and no PSKs
  epoch_secret = MLS::Crypto.expand_with_label(member_secret, "epoch", group_info.group_context.raw, MLS::Crypto.kdf_n_h)
  confirmation_key = MLS::Crypto.derive_secret(epoch_secret, 'confirm')

  ## Recompute a candidate confirmation_tag value using the confirmation_key from the key schedule epoch and the confirmed_transcript_hash from the decrypted GroupContext
  assert_equal group_info.confirmation_tag, MLS::Crypto.mac(confirmation_key, group_info.group_context.confirmed_transcript_hash)
  puts "[s] Recompute a candidate confirmation_tag value using the confirmation_key from the key schedule epoch and the confirmed_transcript_hash from the decrypted GroupContext"
end
