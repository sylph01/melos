require 'json'
require 'minitest'
require 'melos'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

if ENV['TEST_ALL']
  message_protection_vectors = JSON.parse(File.read('test_vectors/message-protection.json'))
else
  message_protection_vectors = JSON.parse(File.read('test_vectors/message-protection.json'))[0..0]
end

message_protection_vectors.each do |mpv|
  suite = Melos::Crypto::CipherSuite.new(mpv['cipher_suite'])
  puts "for cipher suite ID #{mpv['cipher_suite']}:"
  group_id = from_hex(mpv['group_id'])
  epoch = mpv['epoch']

  ## Construct a GroupContext object with the provided cipher_suite, group_id, epoch, tree_hash, and confirmed_transcript_hash values, and empty extensions
  group_context = Melos::Struct::GroupContext.create(
    cipher_suite: mpv['cipher_suite'],
    group_id: group_id,
    epoch: epoch,
    tree_hash: from_hex(mpv['tree_hash']),
    confirmed_transcript_hash: from_hex(mpv['confirmed_transcript_hash']),
    extensions: []
  )

  ## The vector gives the epoch's secrets directly. Each side of a private message holds its own
  ## copy of the epoch (and so its own secret tree), so a fresh one is made wherever the side changes.
  epoch_components = {
    encryption_secret: from_hex(mpv['encryption_secret']),
    sender_data_secret: from_hex(mpv['sender_data_secret']),
    membership_key: from_hex(mpv['membership_key'])
  }
  new_epoch = -> { Melos::EpochSecrets.from_components(suite, n_leaves: 2, **epoch_components) }
  epoch_secrets = new_epoch.()

  signature_pub = from_hex(mpv['signature_pub'])
  signature_priv = from_hex(mpv['signature_priv'])

  ## For each of proposal, commit and application:
  ### proposal
  puts "proposal:"
  proposal = Melos::Struct::Proposal.new(from_hex(mpv['proposal']))
  proposal_pub = Melos::Struct::MLSMessage.new(from_hex(mpv['proposal_pub']))
  proposal_priv = Melos::Struct::MLSMessage.new(from_hex(mpv['proposal_priv']))

  #### Verify that the pub message verifies with the provided membership_key and signature_pub, and produces the raw proposal / commit / application data
  authenticated_content = proposal_pub.public_message.unprotect(suite, epoch_secrets.membership_key, group_context)
  assert_equal true, authenticated_content.verify(suite, signature_pub, group_context)
  puts "[s] pub message verifies with the provided membership_key and signature_pub"
  assert_equal from_hex(mpv['proposal']), proposal_pub.public_message.content.proposal.raw
  puts "[s] produces the raw proposal"

  #### Verify that protecting the raw value with the provided membership_key and signature_priv produces a PublicMessage that verifies with membership_key and signature_pub
  # create FramedContent
  framed_content = Melos::Struct::FramedContent.create(
    group_id: group_id,
    epoch: epoch,
    sender: Melos::Struct::Sender.create_member(1), # sender is leaf index 1
    authenticated_data: "authenticated_data", # 6.3.1: it is up to the application to decide what authenticated_data to provide and how much padding to add to a given message (if any)
    content_type: 0x02, # proposal
    content: proposal
  )
  authenticated_content_2 = Melos::Struct::AuthenticatedContent.create(
    wire_format: 0x01, # public_message
    content: framed_content,
    auth: nil
  )
  authenticated_content_2.sign(suite, signature_priv, group_context)
  public_message_2 = Melos::Struct::PublicMessage.protect(authenticated_content_2, suite, epoch_secrets.membership_key, group_context)
  authenticated_content_3 = public_message_2.unprotect(suite, epoch_secrets.membership_key, group_context)
  puts "[s] protecting the raw value with the provided membership_key and signature_priv produces a PublicMessage that verifies with membership_key and signature_pub"

  #### Verify that the priv message successfully unprotects using the secret tree constructed above and signature_pub
  epoch_secrets = new_epoch.() # the receiver's copy of the epoch
  authenticated_content = proposal_priv.private_message.unprotect(suite, epoch_secrets.secret_tree, epoch_secrets.sender_data_secret)
  assert_equal true, authenticated_content.verify(suite, signature_pub, group_context)
  puts "[s] the priv message successfully unprotects using the secret tree constructed above and signature_pub"

  #### Verify that protecting the raw value with the secret tree, sender_data_secret, and signature_priv produces a PrivateMessage that unprotects with the secret tree, sender_data_secret, and signature_pub
  epoch_secrets = new_epoch.() # the other side's copy of the epoch
  # create FramedContent -> AuthenticatedContent then sign it
  framed_content = Melos::Struct::FramedContent.create(
    group_id: group_id,
    epoch: epoch,
    sender: Melos::Struct::Sender.create_member(1), # sender is leaf index 1
    authenticated_data: "authenticated_data", # 6.3.1: it is up to the application to decide what authenticated_data to provide and how much padding to add to a given message (if any)
    content_type: 0x02, # proposal
    content: proposal
  )
  authenticated_content_4 = Melos::Struct::AuthenticatedContent.create(
    wire_format: 0x02, # private_message
    content: framed_content,
    auth: nil
  )
  authenticated_content_4.sign(suite, signature_priv, group_context)
  private_message_4 = Melos::Struct::PrivateMessage.protect(authenticated_content_4, suite, epoch_secrets.secret_tree, epoch_secrets.sender_data_secret, 7) # padding size is arbitrary

  epoch_secrets = new_epoch.() # the other side's copy of the epoch
  authenticated_content_5 = private_message_4.unprotect(suite, epoch_secrets.secret_tree, epoch_secrets.sender_data_secret)
  assert_equal true, authenticated_content_5.verify(suite, signature_pub, group_context)
  puts "[s] protecting the raw value with the secret tree, sender_data_secret, and signature_priv produces a PrivateMessage that unprotects with the secret tree, sender_data_secret, and signature_pub"

  ### commit
  puts "commit:"
  commit = Melos::Struct::Commit.new(from_hex(mpv['commit']))
  commit_pub = Melos::Struct::MLSMessage.new(from_hex(mpv['commit_pub']))
  commit_priv = Melos::Struct::MLSMessage.new(from_hex(mpv['commit_priv']))

  #### Verify that the pub message verifies with the provided membership_key and signature_pub, and produces the raw proposal / commit / application data
  authenticated_content = commit_pub.public_message.unprotect(suite, epoch_secrets.membership_key, group_context)
  assert_equal true, authenticated_content.verify(suite, signature_pub, group_context)
  puts "[s] pub message verifies with the provided membership_key and signature_pub"
  assert_equal from_hex(mpv['commit']), commit_pub.public_message.content.commit.raw
  puts "[s] produces the raw commit"

  #### Verify that protecting the raw value with the provided membership_key and signature_priv produces a PublicMessage that verifies with membership_key and signature_pub
  # create FramedContent
  framed_content = Melos::Struct::FramedContent.create(
    group_id: group_id,
    epoch: epoch,
    sender: Melos::Struct::Sender.create_member(1), # sender is leaf index 1
    authenticated_data: "authenticated_data", # 6.3.1: it is up to the application to decide what authenticated_data to provide and how much padding to add to a given message (if any)
    content_type: 0x03, # commit
    content: commit
  )
  authenticated_content_2 = Melos::Struct::AuthenticatedContent.create(
    wire_format: 0x01, # public_message
    content: framed_content,
    auth: nil
  )
  authenticated_content_2.sign(suite, signature_priv, group_context)

  ### NOTE: BouncyCastle just derives a key from a zero vector and uses it to construct a confirmation tag. Is that legal...? But we don't have a active key schedule so that might be the way to go
  confirmation_tag = Melos::Crypto.derive_secret(suite, Melos::Crypto::Util.zero_vector(suite.kdf.n_h), "confirmation_tag")
  ### and here we directly set it inside authenticated content...
  authenticated_content_2.auth.instance_variable_set(:@confirmation_tag, confirmation_tag)

  public_message_2 = Melos::Struct::PublicMessage.protect(authenticated_content_2, suite, epoch_secrets.membership_key, group_context)
  authenticated_content_3 = public_message_2.unprotect(suite, epoch_secrets.membership_key, group_context)
  puts "[s] protecting the raw value with the provided membership_key and signature_priv produces a PublicMessage that verifies with membership_key and signature_pub"

  #### Verify that the priv message successfully unprotects using the secret tree constructed above and signature_pub
  epoch_secrets = new_epoch.() # the receiver's copy of the epoch
  authenticated_content = commit_priv.private_message.unprotect(suite, epoch_secrets.secret_tree, epoch_secrets.sender_data_secret)
  assert_equal true, authenticated_content.verify(suite, signature_pub, group_context)
  puts "[s] the priv message successfully unprotects using the secret tree constructed above and signature_pub"

  #### Verify that protecting the raw value with the secret tree, sender_data_secret, and signature_priv produces a PrivateMessage that unprotects with the secret tree, sender_data_secret, and signature_pub
  epoch_secrets = new_epoch.() # the other side's copy of the epoch
  # create FramedContent -> AuthenticatedContent then sign it
  framed_content = Melos::Struct::FramedContent.create(
    group_id: group_id,
    epoch: epoch,
    sender: Melos::Struct::Sender.create_member(1), # sender is leaf index 1
    authenticated_data: "authenticated_data", # 6.3.1: it is up to the application to decide what authenticated_data to provide and how much padding to add to a given message (if any)
    content_type: 0x03, # commit
    content: commit
  )
  authenticated_content_4 = Melos::Struct::AuthenticatedContent.create(
    wire_format: 0x02, # private_message
    content: framed_content,
    auth: nil
  )
  authenticated_content_4.sign(suite, signature_priv, group_context)
  ### and here we directly set it inside authenticated content...
  authenticated_content_4.auth.instance_variable_set(:@confirmation_tag, confirmation_tag)
  private_message_4 = Melos::Struct::PrivateMessage.protect(authenticated_content_4, suite, epoch_secrets.secret_tree, epoch_secrets.sender_data_secret, 7) # padding size is arbitrary

  epoch_secrets = new_epoch.() # the other side's copy of the epoch
  authenticated_content_5 = private_message_4.unprotect(suite, epoch_secrets.secret_tree, epoch_secrets.sender_data_secret)
  assert_equal true, authenticated_content_5.verify(suite, signature_pub, group_context)
  puts "[s] protecting the raw value with the secret tree, sender_data_secret, and signature_priv produces a PrivateMessage that unprotects with the secret tree, sender_data_secret, and signature_pub"

  ### application
  puts "application:"
  application = from_hex(mpv['application'])
  application_priv = Melos::Struct::MLSMessage.new(from_hex(mpv['application_priv']))

  puts "[skip] Verify that the pub message verifies with the provided membership_key and signature_pub, and produces the raw proposal / commit / application data (pub does not exist)"

  ## verify that protecting application message fails
  # create FramedContent
  framed_content = Melos::Struct::FramedContent.create(
    group_id: group_id,
    epoch: epoch,
    sender: Melos::Struct::Sender.create_member(1), # sender is leaf index 1
    authenticated_data: "authenticated_data", # 6.3.1: it is up to the application to decide what authenticated_data to provide and how much padding to add to a given message (if any)
    content_type: 0x01, # commit
    content: application
  )
  authenticated_content_2 = Melos::Struct::AuthenticatedContent.create(
    wire_format: 0x01, # public_message
    content: framed_content,
    auth: nil
  )
  assert_raises ArgumentError do
    authenticated_content_2.sign(suite, signature_priv, group_context)
  end
  puts "[s] verify that protecting application message fails"

  #### Verify that the priv message successfully unprotects using the secret tree constructed above and signature_pub
  epoch_secrets = new_epoch.() # the receiver's copy of the epoch
  authenticated_content = application_priv.private_message.unprotect(suite, epoch_secrets.secret_tree, epoch_secrets.sender_data_secret)
  assert_equal true, authenticated_content.verify(suite, signature_pub, group_context)
  puts "[s] the priv message successfully unprotects using the secret tree constructed above and signature_pub"

  #### Verify that protecting the raw value with the secret tree, sender_data_secret, and signature_priv produces a PrivateMessage that unprotects with the secret tree, sender_data_secret, and signature_pub
  epoch_secrets = new_epoch.() # the other side's copy of the epoch
  # create FramedContent -> AuthenticatedContent then sign it
  framed_content = Melos::Struct::FramedContent.create(
    group_id: group_id,
    epoch: epoch,
    sender: Melos::Struct::Sender.create_member(1), # sender is leaf index 1
    authenticated_data: "authenticated_data", # 6.3.1: it is up to the application to decide what authenticated_data to provide and how much padding to add to a given message (if any)
    content_type: 0x01, # application
    content: application
  )
  authenticated_content_4 = Melos::Struct::AuthenticatedContent.create(
    wire_format: 0x02, # private_message
    content: framed_content,
    auth: nil
  )
  authenticated_content_4.sign(suite, signature_priv, group_context)
  private_message_4 = Melos::Struct::PrivateMessage.protect(authenticated_content_4, suite, epoch_secrets.secret_tree, epoch_secrets.sender_data_secret, 7) # padding size is arbitrary

  epoch_secrets = new_epoch.() # the other side's copy of the epoch
  authenticated_content_5 = private_message_4.unprotect(suite, epoch_secrets.secret_tree, epoch_secrets.sender_data_secret)
  assert_equal true, authenticated_content_5.verify(suite, signature_pub, group_context)
  puts "[s] protecting the raw value with the secret tree, sender_data_secret, and signature_priv produces a PrivateMessage that unprotects with the secret tree, sender_data_secret, and signature_pub"

end
