require 'json'
require_relative 'lib/mls'
require 'minitest'
include Minitest::Assertions
include MLS::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

psk_vectors = JSON.parse(File.read('test_vectors/psk_secret.json'))
psk_vectors.each_with_index do |psk_vector, total_idx|
  suite = MLS::Crypto::CipherSuite.new(psk_vector['cipher_suite'])
  zero_vector = MLS::Crypto::Util.zero_vector(suite.kdf.n_h)
  puts "vector #{total_idx}, cipher_suite #{psk_vector["cipher_suite"]}"

  psk_secret = zero_vector
  psk_vector['psks'].each_with_index do |psk, idx|
    psk_id    = from_hex(psk['psk_id'])
    psk_value = from_hex(psk['psk'])
    psk_nonce = from_hex(psk['psk_nonce'])

    preshared_key_id = MLS::Struct::PreSharedKeyID.create_external(
      psk_id: psk_id,
      psk_nonce: psk_nonce
    )

    psk_label = MLS::Struct::PSKLabel.create(
      id: preshared_key_id,
      index: idx,
      count: psk_vector['psks'].count
    )

    psk_extracted = MLS::Crypto.kdf_extract(suite, zero_vector, psk_value)
    # puts to_hex(preshared_key_id.raw)
    # puts to_hex(psk_label.raw)
    psk_input     = MLS::Crypto.expand_with_label(
      suite,
      psk_extracted,
      "derived psk",
      psk_label.raw,
      suite.kdf.n_h
    )
    psk_secret = MLS::Crypto.kdf_extract(suite, psk_input, psk_secret)
  end
  # do stuff
  assert_equal to_hex(psk_secret), psk_vector['psk_secret']
  puts "[s] psk_secret"
end
