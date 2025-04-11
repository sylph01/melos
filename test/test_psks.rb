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
  psk_vectors = JSON.parse(File.read('test_vectors/psk_secret.json'))
else
  psk_vectors = JSON.parse(File.read('test_vectors/psk_secret.json'))[0..9]
end

psk_vectors.each_with_index do |psk_vector, total_idx|
  suite = Melos::Crypto::CipherSuite.new(psk_vector['cipher_suite'])
  zero_vector = Melos::Crypto::Util.zero_vector(suite.kdf.n_h)
  puts "vector #{total_idx}, cipher_suite #{psk_vector["cipher_suite"]}"

  psk_secret = zero_vector
  psk_array = psk_vector['psks'].map {
    preshared_key_id = Melos::Struct::PreSharedKeyID.create_external(
      psk_id: from_hex(_1['psk_id']),
      psk_nonce: from_hex(_1['psk_nonce'])
    )
    [preshared_key_id.raw, from_hex(_1['psk'])]
  }

  assert_equal from_hex(psk_vector['psk_secret']), Melos::PSK.psk_secret(suite, psk_array)
  puts "[s] psk_secret"
end
