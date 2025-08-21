require 'minitest'
require 'melos'
include Minitest::Assertions
include Melos::Util

class << self
  attr_accessor :assertions
end
self.assertions = 0

puts "Testing ProposalFactory..."

# Test Remove Proposal Creation
puts "Testing remove proposal creation..."
remove_proposal = Melos::ProposalFactory.create_remove_proposal(removed_leaf_index: 42)
assert_equal Melos::Struct::Proposal, remove_proposal.class
assert_equal Melos::Constants::ProposalType::REMOVE, remove_proposal.proposal_type
assert_equal 42, remove_proposal.remove.removed
puts "[✓] Remove proposal created successfully"

# Test PSK Proposal Creation
puts "Testing PSK proposal creation..."
psk_proposal = Melos::ProposalFactory.create_psk_proposal(
  psk_id: "test_psk_id",
  psk_nonce: "test_nonce"
)
assert_equal Melos::Struct::Proposal, psk_proposal.class
assert_equal Melos::Constants::ProposalType::PSK, psk_proposal.proposal_type
assert_equal Melos::Constants::PSKType::EXTERNAL, psk_proposal.psk.psk.psktype
assert_equal "test_psk_id", psk_proposal.psk.psk.psk_id
assert_equal "test_nonce", psk_proposal.psk.psk.psk_nonce
puts "[✓] PSK proposal created successfully"

# Test ReInit Proposal Creation
puts "Testing ReInit proposal creation..."
reinit_proposal = Melos::ProposalFactory.create_reinit_proposal(
  group_id: "new_group_id",
  version: Melos::Constants::Version::MLS10,
  cipher_suite: 0x0001,
  extensions: []
)
assert_equal Melos::Struct::Proposal, reinit_proposal.class
assert_equal Melos::Constants::ProposalType::REINIT, reinit_proposal.proposal_type
assert_equal "new_group_id", reinit_proposal.reinit.group_id
assert_equal Melos::Constants::Version::MLS10, reinit_proposal.reinit.version
assert_equal 0x0001, reinit_proposal.reinit.cipher_suite
assert_equal [], reinit_proposal.reinit.extensions
puts "[✓] ReInit proposal created successfully"

# Test ExternalInit Proposal Creation
puts "Testing ExternalInit proposal creation..."
external_init_proposal = Melos::ProposalFactory.create_external_init_proposal(
  kem_output: "test_kem_output"
)
assert_equal Melos::Struct::Proposal, external_init_proposal.class
assert_equal Melos::Constants::ProposalType::EXTERNAL_INIT, external_init_proposal.proposal_type
assert_equal "test_kem_output", external_init_proposal.external_init.kem_output
puts "[✓] ExternalInit proposal created successfully"

# Test GroupContextExtensions Proposal Creation
puts "Testing GroupContextExtensions proposal creation..."
extensions = []
gce_proposal = Melos::ProposalFactory.create_group_context_extensions_proposal(
  extensions: extensions
)
assert_equal Melos::Struct::Proposal, gce_proposal.class
assert_equal Melos::Constants::ProposalType::GROUP_CONTEXT_EXTENSIONS, gce_proposal.proposal_type
assert_equal extensions, gce_proposal.group_context_extensions.extensions
puts "[✓] GroupContextExtensions proposal created successfully"

# Test ProposalOrRef Creation from Proposal
puts "Testing ProposalOrRef creation from proposal..."
proposal_or_ref = Melos::ProposalFactory.create_proposal_or_ref_from_proposal(
  proposal: remove_proposal
)
assert_equal Melos::Struct::ProposalOrRef, proposal_or_ref.class
assert_equal Melos::Constants::ProposalOrRefType::PROPOSAL, proposal_or_ref.type
assert_equal remove_proposal, proposal_or_ref.proposal
puts "[✓] ProposalOrRef from proposal created successfully"

# Test ProposalOrRef Creation from Reference
puts "Testing ProposalOrRef creation from reference..."
reference_or_ref = Melos::ProposalFactory.create_proposal_or_ref_from_reference(
  reference: "sample_hash_reference"
)
assert_equal Melos::Struct::ProposalOrRef, reference_or_ref.class
assert_equal Melos::Constants::ProposalOrRefType::REFERENCE, reference_or_ref.type
assert_equal "sample_hash_reference", reference_or_ref.reference
puts "[✓] ProposalOrRef from reference created successfully"

puts "All ProposalFactory tests passed! ✅"
