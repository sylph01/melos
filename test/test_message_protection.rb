require 'json'
require 'minitest'
require 'mls'
include Minitest::Assertions
include MLS::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

message_protection_vectors = JSON.parse(File.read('test_vectors/message-protection.json'))[0..0]

message_protection_vectors.each do |mpv|
  suite = MLS::Crypto::CipherSuite.new(mpv['cipher_suite'])
  puts "for cipher suite ID #{mpv['cipher_suite']}:"
  group_id = from_hex(mpv['group_id'])
  epoch = mpv['epoch']

  ## Construct a GroupContext object with the provided cipher_suite, group_id, epoch, tree_hash, and confirmed_transcript_hash values, and empty extensions
  group_context = MLS::Struct::GroupContext.create(
    cipher_suite: mpv['cipher_suite'],
    group_id: group_id,
    epoch: epoch,
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
  proposal = MLS::Struct::Proposal.new(from_hex(mpv['proposal']))
  proposal_pub = MLS::Struct::MLSMessage.new(from_hex(mpv['proposal_pub']))
  proposal_priv = MLS::Struct::MLSMessage.new(from_hex(mpv['proposal_priv']))

  #### Verify that the pub message verifies with the provided membership_key and signature_pub, and produces the raw proposal / commit / application data
  authenticated_content = proposal_pub.public_message.unprotect(suite, membership_key, group_context)
  assert_equal true, authenticated_content.verify(suite, signature_pub, group_context)
  puts "[s] pub message verifies with the provided membership_key and signature_pub"
  assert_equal from_hex(mpv['proposal']), proposal_pub.public_message.content.proposal.raw
  puts "[s] produces the raw proposal"

  #### Verify that protecting the raw value with the provided membership_key and signature_priv produces a PublicMessage that verifies with membership_key and signature_pub
  # create FramedContent
  framed_content = MLS::Struct::FramedContent.create(
    group_id: group_id,
    epoch: epoch,
    sender: MLS::Struct::Sender.create_member(1), # sender is leaf index 1
    authenticated_data: "authenticated_data", # 6.3.1: it is up to the application to decide what authenticated_data to provide and how much padding to add to a given message (if any)
    content_type: 0x02, # proposal
    content: proposal
  )
  authenticated_content_2 = MLS::Struct::AuthenticatedContent.create(
    wire_format: 0x01, # public_message
    content: framed_content,
    auth: nil
  )
  authenticated_content_2.sign(suite, signature_priv, group_context)
  public_message_2 = MLS::Struct::PublicMessage.protect(authenticated_content_2, suite, membership_key, group_context)
  authenticated_content_3 = public_message_2.unprotect(suite, membership_key, group_context)
  puts "[s] protecting the raw value with the provided membership_key and signature_priv produces a PublicMessage that verifies with membership_key and signature_pub"

  #### Verify that the priv message successfully unprotects using the secret tree constructed above and signature_pub
  secret_tree = MLS::SecretTree.create(suite, 2, encryption_secret)
  authenticated_content = proposal_priv.private_message.unprotect(suite, secret_tree, sender_data_secret)
  assert_equal true, authenticated_content.verify(suite, signature_pub, group_context)
  puts "[s] the priv message successfully unprotects using the secret tree constructed above and signature_pub"

  #### Verify that protecting the raw value with the secret tree, sender_data_secret, and signature_priv produces a PrivateMessage that unprotects with the secret tree, sender_data_secret, and signature_pub
  # reset secret tree
  secret_tree = MLS::SecretTree.create(suite, 2, encryption_secret)
  # create FramedContent -> AuthenticatedContent then sign it
  framed_content = MLS::Struct::FramedContent.create(
    group_id: group_id,
    epoch: epoch,
    sender: MLS::Struct::Sender.create_member(1), # sender is leaf index 1
    authenticated_data: "authenticated_data", # 6.3.1: it is up to the application to decide what authenticated_data to provide and how much padding to add to a given message (if any)
    content_type: 0x02, # proposal
    content: proposal
  )
  authenticated_content_4 = MLS::Struct::AuthenticatedContent.create(
    wire_format: 0x02, # private_message
    content: framed_content,
    auth: nil
  )
  authenticated_content_4.sign(suite, signature_priv, group_context)
  private_message_4 = MLS::Struct::PrivateMessage.protect(authenticated_content_4, suite, secret_tree, sender_data_secret, 7) # padding size is arbitrary

  # reset secret tree
  secret_tree = MLS::SecretTree.create(suite, 2, encryption_secret)
  authenticated_content_5 = private_message_4.unprotect(suite, secret_tree, sender_data_secret)
  assert_equal true, authenticated_content_5.verify(suite, signature_pub, group_context)
  puts "[s] protecting the raw value with the secret tree, sender_data_secret, and signature_priv produces a PrivateMessage that unprotects with the secret tree, sender_data_secret, and signature_pub"

  ### commit
  puts "commit:"
  commit = MLS::Struct::Commit.new(from_hex(mpv['commit']))
  commit_pub = MLS::Struct::MLSMessage.new(from_hex(mpv['commit_pub']))
  commit_priv = MLS::Struct::MLSMessage.new(from_hex(mpv['commit_priv']))

  #### Verify that the pub message verifies with the provided membership_key and signature_pub, and produces the raw proposal / commit / application data
  authenticated_content = commit_pub.public_message.unprotect(suite, membership_key, group_context)
  assert_equal true, authenticated_content.verify(suite, signature_pub, group_context)
  puts "[s] pub message verifies with the provided membership_key and signature_pub"
  assert_equal from_hex(mpv['commit']), commit_pub.public_message.content.commit.raw
  puts "[s] produces the raw commit"

  #### Verify that protecting the raw value with the provided membership_key and signature_priv produces a PublicMessage that verifies with membership_key and signature_pub
  # create FramedContent
  framed_content = MLS::Struct::FramedContent.create(
    group_id: group_id,
    epoch: epoch,
    sender: MLS::Struct::Sender.create_member(1), # sender is leaf index 1
    authenticated_data: "authenticated_data", # 6.3.1: it is up to the application to decide what authenticated_data to provide and how much padding to add to a given message (if any)
    content_type: 0x03, # commit
    content: commit
  )
  authenticated_content_2 = MLS::Struct::AuthenticatedContent.create(
    wire_format: 0x01, # public_message
    content: framed_content,
    auth: nil
  )
  authenticated_content_2.sign(suite, signature_priv, group_context)

  ### NOTE: BouncyCastle just derives a key from a zero vector and uses it to construct a confirmation tag. Is that legal...? But we don't have a active key schedule so that might be the way to go
  confirmation_tag = MLS::Crypto.derive_secret(suite, MLS::Crypto::Util.zero_vector(suite.kdf.n_h), "confirmation_tag")
  ### and here we directly set it inside authenticated content...
  authenticated_content_2.auth.instance_variable_set(:@confirmation_tag, confirmation_tag)

  public_message_2 = MLS::Struct::PublicMessage.protect(authenticated_content_2, suite, membership_key, group_context)
  authenticated_content_3 = public_message_2.unprotect(suite, membership_key, group_context)
  puts "[s] protecting the raw value with the provided membership_key and signature_priv produces a PublicMessage that verifies with membership_key and signature_pub"

  #### Verify that the priv message successfully unprotects using the secret tree constructed above and signature_pub
  secret_tree = MLS::SecretTree.create(suite, 2, encryption_secret)
  authenticated_content = commit_priv.private_message.unprotect(suite, secret_tree, sender_data_secret)
  assert_equal true, authenticated_content.verify(suite, signature_pub, group_context)
  puts "[s] the priv message successfully unprotects using the secret tree constructed above and signature_pub"

  #### Verify that protecting the raw value with the secret tree, sender_data_secret, and signature_priv produces a PrivateMessage that unprotects with the secret tree, sender_data_secret, and signature_pub
  # reset secret tree
  secret_tree = MLS::SecretTree.create(suite, 2, encryption_secret)
  # create FramedContent -> AuthenticatedContent then sign it
  framed_content = MLS::Struct::FramedContent.create(
    group_id: group_id,
    epoch: epoch,
    sender: MLS::Struct::Sender.create_member(1), # sender is leaf index 1
    authenticated_data: "authenticated_data", # 6.3.1: it is up to the application to decide what authenticated_data to provide and how much padding to add to a given message (if any)
    content_type: 0x03, # commit
    content: commit
  )
  authenticated_content_4 = MLS::Struct::AuthenticatedContent.create(
    wire_format: 0x02, # private_message
    content: framed_content,
    auth: nil
  )
  authenticated_content_4.sign(suite, signature_priv, group_context)
  ### and here we directly set it inside authenticated content...
  authenticated_content_4.auth.instance_variable_set(:@confirmation_tag, confirmation_tag)
  private_message_4 = MLS::Struct::PrivateMessage.protect(authenticated_content_4, suite, secret_tree, sender_data_secret, 7) # padding size is arbitrary

  # reset secret tree
  secret_tree = MLS::SecretTree.create(suite, 2, encryption_secret)
  authenticated_content_5 = private_message_4.unprotect(suite, secret_tree, sender_data_secret)
  assert_equal true, authenticated_content_5.verify(suite, signature_pub, group_context)
  puts "[s] protecting the raw value with the secret tree, sender_data_secret, and signature_priv produces a PrivateMessage that unprotects with the secret tree, sender_data_secret, and signature_pub"

  ### application
  puts "application:"
  application = from_hex(mpv['application'])
  application_priv = MLS::Struct::MLSMessage.new(from_hex(mpv['application_priv']))

  puts "[skip] Verify that the pub message verifies with the provided membership_key and signature_pub, and produces the raw proposal / commit / application data (pub does not exist)"

  ## verify that protecting application message fails
  # create FramedContent
  framed_content = MLS::Struct::FramedContent.create(
    group_id: group_id,
    epoch: epoch,
    sender: MLS::Struct::Sender.create_member(1), # sender is leaf index 1
    authenticated_data: "authenticated_data", # 6.3.1: it is up to the application to decide what authenticated_data to provide and how much padding to add to a given message (if any)
    content_type: 0x01, # commit
    content: application
  )
  authenticated_content_2 = MLS::Struct::AuthenticatedContent.create(
    wire_format: 0x01, # public_message
    content: framed_content,
    auth: nil
  )
  assert_raises ArgumentError do
    authenticated_content_2.sign(suite, signature_priv, group_context)
  end
  puts "[s] verify that protecting application message fails"

  #### Verify that the priv message successfully unprotects using the secret tree constructed above and signature_pub
  secret_tree = MLS::SecretTree.create(suite, 2, encryption_secret)
  authenticated_content = application_priv.private_message.unprotect(suite, secret_tree, sender_data_secret)
  assert_equal true, authenticated_content.verify(suite, signature_pub, group_context)
  puts "[s] the priv message successfully unprotects using the secret tree constructed above and signature_pub"

  #### Verify that protecting the raw value with the secret tree, sender_data_secret, and signature_priv produces a PrivateMessage that unprotects with the secret tree, sender_data_secret, and signature_pub
  # reset secret tree
  secret_tree = MLS::SecretTree.create(suite, 2, encryption_secret)
  # create FramedContent -> AuthenticatedContent then sign it
  framed_content = MLS::Struct::FramedContent.create(
    group_id: group_id,
    epoch: epoch,
    sender: MLS::Struct::Sender.create_member(1), # sender is leaf index 1
    authenticated_data: "authenticated_data", # 6.3.1: it is up to the application to decide what authenticated_data to provide and how much padding to add to a given message (if any)
    content_type: 0x01, # application
    content: application
  )
  authenticated_content_4 = MLS::Struct::AuthenticatedContent.create(
    wire_format: 0x02, # private_message
    content: framed_content,
    auth: nil
  )
  authenticated_content_4.sign(suite, signature_priv, group_context)
  private_message_4 = MLS::Struct::PrivateMessage.protect(authenticated_content_4, suite, secret_tree, sender_data_secret, 7) # padding size is arbitrary

  # reset secret tree
  secret_tree = MLS::SecretTree.create(suite, 2, encryption_secret)
  authenticated_content_5 = private_message_4.unprotect(suite, secret_tree, sender_data_secret)
  assert_equal true, authenticated_content_5.verify(suite, signature_pub, group_context)
  puts "[s] protecting the raw value with the secret tree, sender_data_secret, and signature_priv produces a PrivateMessage that unprotects with the secret tree, sender_data_secret, and signature_pub"

end
