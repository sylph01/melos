require 'json'
require 'mls'
require 'minitest'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

if ENV['TEST_ALL']
  crypto_vectors = JSON.parse(File.read('test_vectors/crypto-basics.json'))
else
  crypto_vectors = JSON.parse(File.read('test_vectors/crypto-basics.json'))[0..0]
end

crypto_vectors.each_with_index do |vector, index|
  suite = Melos::Crypto::CipherSuite.new(vector['cipher_suite'])
  puts "for cipher suite ID #{vector['cipher_suite']}:"

  # RefHash
  ref_hash = Melos::Crypto.ref_hash(suite, vector['ref_hash']['label'], from_hex(vector['ref_hash']['value']))
  assert_equal to_hex(ref_hash), vector['ref_hash']['out']
  puts "[s] ref_hash"

  # expand_with_label
  out = Melos::Crypto.expand_with_label(
    suite,
    from_hex(vector['expand_with_label']['secret']),
    vector['expand_with_label']['label'],
    from_hex(vector['expand_with_label']['context']),
    vector['expand_with_label']['length']
  )
  assert_equal to_hex(out), vector['expand_with_label']['out']
  puts "[s] expand_with_label"

  # derive_secret
  out = Melos::Crypto.derive_secret(
    suite,
    from_hex(vector['derive_secret']['secret']),
    vector['derive_secret']['label']
  )
  assert_equal to_hex(out), vector['derive_secret']['out']
  puts "[s] derive_secret"

  # derive_tree_secret
  out = Melos::Crypto.derive_tree_secret(
    suite,
    from_hex(vector['derive_tree_secret']['secret']),
    vector['derive_tree_secret']['label'],
    vector['derive_tree_secret']['generation'],
    vector['derive_tree_secret']['length'],
  )
  assert_equal to_hex(out), vector['derive_tree_secret']['out']
  puts "[s] derive_tree_secret"

  # encrypt_with_label
  priv = from_hex(vector['encrypt_with_label']['priv'])
  pub = from_hex(vector['encrypt_with_label']['pub'])
  label = vector['encrypt_with_label']['label']
  context = from_hex(vector['encrypt_with_label']['context'])
  plaintext = from_hex(vector['encrypt_with_label']['plaintext'])
  kem_output = from_hex(vector['encrypt_with_label']['kem_output'])
  ciphertext = from_hex(vector['encrypt_with_label']['ciphertext'])

  pt = Melos::Crypto.decrypt_with_label(
    suite,
    priv,
    label,
    context,
    kem_output,
    ciphertext
  )
  assert_equal pt, plaintext

  kem_output_candidate, ciphertext_candidate = Melos::Crypto.encrypt_with_label(
    suite,
    pub,
    label,
    context,
    plaintext
  )
  pt2 = Melos::Crypto.decrypt_with_label(
    suite,
    priv,
    label,
    context,
    kem_output_candidate,
    ciphertext_candidate
  )
  assert_equal pt2, plaintext
  puts "[s] encrypt_with_label"

  # sign_with_label
  priv = from_hex(vector['sign_with_label']['priv'])
  pub = from_hex(vector['sign_with_label']['pub'])
  content = from_hex(vector['sign_with_label']['content'])
  label = vector['sign_with_label']['label']
  signature = from_hex(vector['sign_with_label']['signature'])

  assert_equal true, Melos::Crypto.verify_with_label(
    suite, pub, label, content, signature
  )
  # all suites pass this
  assert_equal true, Melos::Crypto.verify_with_label(
    suite, pub, label, content,
    Melos::Crypto.sign_with_label(suite, priv, label, content)
  )
  puts "[s] sign_with_label"
end
