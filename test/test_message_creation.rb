require 'minitest'
require 'melos'
include Minitest::Assertions
include Melos::Util

class << self
  attr_accessor :assertions
end
self.assertions = 0

puts "Testing Message Creation Methods..."

# Test Add Creation
puts "Testing Add.create..."
dummy_key_package = Melos::Struct::KeyPackage.allocate
add = Melos::Struct::Add.create(key_package: dummy_key_package)
assert_equal Melos::Struct::Add, add.class
assert_equal dummy_key_package, add.key_package
puts "[✓] Add.create works"

# Test Update Creation
puts "Testing Update.create..."
dummy_leaf_node = Melos::Struct::LeafNode.allocate
update = Melos::Struct::Update.create(leaf_node: dummy_leaf_node)
assert_equal Melos::Struct::Update, update.class
assert_equal dummy_leaf_node, update.leaf_node
puts "[✓] Update.create works"

# Test Remove Creation
puts "Testing Remove.create..."
remove = Melos::Struct::Remove.create(removed: 123)
assert_equal Melos::Struct::Remove, remove.class
assert_equal 123, remove.removed
puts "[✓] Remove.create works"

# Test PreSharedKey Creation
puts "Testing PreSharedKey.create..."
dummy_psk_id = Melos::Struct::PreSharedKeyID.allocate
psk = Melos::Struct::PreSharedKey.create(psk: dummy_psk_id)
assert_equal Melos::Struct::PreSharedKey, psk.class
assert_equal dummy_psk_id, psk.psk
puts "[✓] PreSharedKey.create works"

# Test ReInit Creation
puts "Testing ReInit.create..."
reinit = Melos::Struct::ReInit.create(
  group_id: "test_group",
  version: 1,
  cipher_suite: 0x0001,
  extensions: []
)
assert_equal Melos::Struct::ReInit, reinit.class
assert_equal "test_group", reinit.group_id
assert_equal 1, reinit.version
assert_equal 0x0001, reinit.cipher_suite
assert_equal [], reinit.extensions
puts "[✓] ReInit.create works"

# Test ExternalInit Creation
puts "Testing ExternalInit.create..."
external_init = Melos::Struct::ExternalInit.create(kem_output: "test_kem")
assert_equal Melos::Struct::ExternalInit, external_init.class
assert_equal "test_kem", external_init.kem_output
puts "[✓] ExternalInit.create works"

# Test GroupContextExtensions Creation
puts "Testing GroupContextExtensions.create..."
gce = Melos::Struct::GroupContextExtensions.create(extensions: [])
assert_equal Melos::Struct::GroupContextExtensions, gce.class
assert_equal [], gce.extensions
puts "[✓] GroupContextExtensions.create works"

# Test Proposal Creation Methods
puts "Testing Proposal creation methods..."

proposal_add = Melos::Struct::Proposal.create_add(add: add)
assert_equal Melos::Struct::Proposal, proposal_add.class
assert_equal Melos::Constants::ProposalType::ADD, proposal_add.proposal_type
assert_equal add, proposal_add.add
puts "[✓] Proposal.create_add works"

proposal_update = Melos::Struct::Proposal.create_update(update: update)
assert_equal Melos::Struct::Proposal, proposal_update.class
assert_equal Melos::Constants::ProposalType::UPDATE, proposal_update.proposal_type
assert_equal update, proposal_update.update
puts "[✓] Proposal.create_update works"

proposal_remove = Melos::Struct::Proposal.create_remove(remove: remove)
assert_equal Melos::Struct::Proposal, proposal_remove.class
assert_equal Melos::Constants::ProposalType::REMOVE, proposal_remove.proposal_type
assert_equal remove, proposal_remove.remove
puts "[✓] Proposal.create_remove works"

# Test ProposalOrRef Creation
puts "Testing ProposalOrRef.create..."
proposal_or_ref = Melos::Struct::ProposalOrRef.create(
  type: Melos::Constants::ProposalOrRefType::PROPOSAL,
  proposal: proposal_add
)
assert_equal Melos::Struct::ProposalOrRef, proposal_or_ref.class
assert_equal Melos::Constants::ProposalOrRefType::PROPOSAL, proposal_or_ref.type
assert_equal proposal_add, proposal_or_ref.proposal
puts "[✓] ProposalOrRef.create with proposal works"

reference_or_ref = Melos::Struct::ProposalOrRef.create(
  type: Melos::Constants::ProposalOrRefType::REFERENCE,
  reference: "hash_ref"
)
assert_equal Melos::Struct::ProposalOrRef, reference_or_ref.class
assert_equal Melos::Constants::ProposalOrRefType::REFERENCE, reference_or_ref.type
assert_equal "hash_ref", reference_or_ref.reference
puts "[✓] ProposalOrRef.create with reference works"

# Test Commit Creation
puts "Testing Commit.create..."
commit = Melos::Struct::Commit.create(
  proposals: [proposal_or_ref],
  path: nil
)
assert_equal Melos::Struct::Commit, commit.class
assert_equal [proposal_or_ref], commit.proposals
assert_nil commit.path
puts "[✓] Commit.create works"

# Test MLSMessage Creation Methods
puts "Testing MLSMessage creation methods..."

dummy_public_message = Melos::Struct::PublicMessage.allocate
public_mls_message = Melos::Struct::MLSMessage.create_public_message(
  public_message: dummy_public_message
)
assert_equal Melos::Struct::MLSMessage, public_mls_message.class
assert_equal Melos::Constants::Version::MLS10, public_mls_message.version
assert_equal Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE, public_mls_message.wire_format
assert_equal dummy_public_message, public_mls_message.public_message
puts "[✓] MLSMessage.create_public_message works"

dummy_private_message = Melos::Struct::PrivateMessage.allocate
private_mls_message = Melos::Struct::MLSMessage.create_private_message(
  private_message: dummy_private_message
)
assert_equal Melos::Struct::MLSMessage, private_mls_message.class
assert_equal Melos::Constants::Version::MLS10, private_mls_message.version
assert_equal Melos::Constants::WireFormat::MLS_PRIVATE_MESSAGE, private_mls_message.wire_format
assert_equal dummy_private_message, private_mls_message.private_message
puts "[✓] MLSMessage.create_private_message works"

# Test FramedContentAuthData Creation
puts "Testing FramedContentAuthData creation methods..."
auth_data = Melos::Struct::FramedContentAuthData.create(
  signature: "test_signature",
  content_type: Melos::Constants::ContentType::PROPOSAL
)
assert_equal Melos::Struct::FramedContentAuthData, auth_data.class
assert_equal "test_signature", auth_data.signature
assert_equal Melos::Constants::ContentType::PROPOSAL, auth_data.content_type
puts "[✓] FramedContentAuthData.create works"

auth_data_signature = Melos::Struct::FramedContentAuthData.create_signature_auth(
  signature: "test_sig",
  content_type: Melos::Constants::ContentType::APPLICATION
)
assert_equal Melos::Struct::FramedContentAuthData, auth_data_signature.class
assert_equal "test_sig", auth_data_signature.signature
assert_equal Melos::Constants::ContentType::APPLICATION, auth_data_signature.content_type
puts "[✓] FramedContentAuthData.create_signature_auth works"

# Test PrivateMessageContent Creation
puts "Testing PrivateMessageContent creation methods..."
dummy_auth = Melos::Struct::FramedContentAuthData.allocate
app_content = Melos::Struct::PrivateMessageContent.create_application(
  application_data: "hello world",
  auth: dummy_auth,
  padding_size: 10
)
assert_equal Melos::Struct::PrivateMessageContent, app_content.class
assert_equal "hello world", app_content.application_data
assert_equal dummy_auth, app_content.auth
assert_equal "\x00" * 10, app_content.padding
puts "[✓] PrivateMessageContent.create_application works"

proposal_content = Melos::Struct::PrivateMessageContent.create_proposal(
  proposal: proposal_add,
  auth: dummy_auth,
  padding_size: 5
)
assert_equal Melos::Struct::PrivateMessageContent, proposal_content.class
assert_equal proposal_add, proposal_content.proposal
assert_equal dummy_auth, proposal_content.auth
assert_equal "\x00" * 5, proposal_content.padding
puts "[✓] PrivateMessageContent.create_proposal works"

puts "All Message Creation tests passed! ✅"
