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
  transcript_hash_vectors = JSON.parse(File.read('test_vectors/transcript-hashes.json'))
else
  transcript_hash_vectors = JSON.parse(File.read('test_vectors/transcript-hashes.json'))[0..0]
end

transcript_hash_vectors.each do |thv|
  suite = Melos::Crypto::CipherSuite.new(thv['cipher_suite'])
  puts "cipher suite #{thv['cipher_suite']}:"

  confirmation_key = from_hex(thv['confirmation_key'])
  authenticated_content_val = from_hex(thv['authenticated_content'])
  authenticated_content = Melos::Struct::AuthenticatedContent.new(authenticated_content_val)

  interim_transcript_hash = from_hex(thv['interim_transcript_hash_before'])

  ## Check content_type being commit
  assert_equal 0x03, authenticated_content.content.content_type
  puts "[s] AuthenticatedContent has Commit type"

  ## MAC, check confirmation tag
  assert_equal authenticated_content.auth.confirmation_tag, Melos::Crypto.mac(suite, confirmation_key, from_hex(thv['confirmed_transcript_hash_after']))
  puts "[s] AuthenticatedContent's FCAD's ConfirmationTag matches MAC"

  ## construct ConfirmedTranscriptHashInput

  cth = Melos::Crypto.hash(
    suite,
    interim_transcript_hash + authenticated_content.confirmed_transcript_hash_input.raw
  )
  ith_next = Melos::Crypto.hash(
    suite,
    cth + Melos::Vec.string_to_vec(authenticated_content.auth.confirmation_tag)
  )

  assert_equal to_hex(cth), thv['confirmed_transcript_hash_after']
  puts "[s] ConfirmedTranscriptHash matches"

  assert_equal to_hex(ith_next), thv['interim_transcript_hash_after']
  puts "[s] InterimTranscriptHash matches"

  ## construct next interim_transcript_hash
end
