require 'json'
require 'minitest'
require_relative 'structs'
require_relative 'tree'
require_relative 'crypto'
require_relative 'vec_base'
require_relative 'secret_tree'
include Minitest::Assertions

class << self
attr_accessor :assertions
end
self.assertions = 0

message_protection_vectors = JSON.parse(File.read('test_vectors/message-protection.json'))[0..0]

message_protection_vectors.each do |mpv|
  suite = MLS::Crypto::CipherSuite.new(mpv['cipher_suite'])
  puts "for cipher suite ID #{mpv['cipher_suite']}:"

  ## Construct a GroupContext object with the provided cipher_suite, group_id, epoch, tree_hash, and confirmed_transcript_hash values, and empty extensions
  group_context = MLSStruct::GroupContext.create(
    cipher_suite: mpv['cipher_suite'],
    group_id: from_hex(mpv['group_id']),
    epoch: mpv['epoch'],
    tree_hash: from_hex(mpv['tree_hash']),
    confirmed_transcript_hash: from_hex(mpv['confirmed_transcript_hash']),
    extensions: []
  )

  encryption_secret = from_hex(mpv['encryption_secret'])
  sender_data_secret = from_hex(mpv['sender_data_secret'])
  membership_key = from_hex(mpv['membership_key'])

  # sender_data_key   = MLS::SecretTree.sender_data_key(suite, sender_data_secret, ciphertext)
  # sender_data_nonce = MLS::SecretTree.sender_data_nonce(suite, sender_data_secret, ciphertext)

  signature_pub = from_hex(mpv['signature_pub'])
  signature_priv = from_hex(mpv['signature_priv'])

  ## For each of proposal, commit and application:
  ### proposal
  puts "proposal:"
  proposal = MLSStruct::Proposal.new(from_hex(mpv['proposal']))
  proposal_pub = MLSStruct::MLSMessage.new(from_hex(mpv['proposal_pub']))
  proposal_priv = MLSStruct::MLSMessage.new(from_hex(mpv['proposal_priv']))

  #### Verify that the pub message verifies with the provided membership_key and signature_pub, and produces the raw proposal / commit / application data
  authenticated_content = proposal_pub.public_message.unprotect(suite, membership_key, group_context)
  assert_equal true, authenticated_content.verify(suite, signature_pub, group_context)
  puts "[s] pub message verifies with the provided membership_key and signature_pub"
  assert_equal from_hex(mpv['proposal']), proposal_pub.public_message.content.proposal.raw
  puts "[s] produces the raw proposal"

  #### Verify that protecting the raw value with the provided membership_key and signature_priv produces a PublicMessage that verifies with membership_key and signature_pub
  #### TODO

  #### Verify that the priv message successfully unprotects using the secret tree constructed above and signature_pub
  secret_tree = MLS::SecretTree.create(suite, 2, encryption_secret)
  authenticated_content = proposal_priv.private_message.unprotect(suite, secret_tree, sender_data_secret)
  assert_equal true, authenticated_content.verify(suite, signature_pub, group_context)
  puts "[s] the priv message successfully unprotects using the secret tree constructed above and signature_pub"

  #### Verify that protecting the raw value with the secret tree, sender_data_secret, and signature_priv produces a PrivateMessage that unprotects with the secret tree, sender_data_secret, and signature_pub
  #### TODO

  ### commit

  ### application
end
