require 'minitest'
require 'melos'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

# Error cases: inputs that RFC 9420 says MUST be rejected. See docs/validation.md.

def wire(message)
  Melos::Struct::MLSMessage.new(message.raw)
end

# a two-member group: returns [alice_group, bob_group, alice, bob]
def two_member_group(suite_id)
  alice = Melos::Client.new(suite_id, identity: 'alice')
  bob = Melos::Client.new(suite_id, identity: 'bob')
  alice_group = alice.create_group("validation-#{suite_id}")
  alice_group.create_add_proposal(wire(bob.create_key_package.message))
  result = alice_group.create_commit
  bob_group = bob.join_group(wire(result.welcome))
  alice_group.merge_commit(result.staged)
  [alice_group, bob_group, alice, bob]
end

suite_id = 1
suite = Melos::Crypto::CipherSuite.new(suite_id)
C = Melos::Constants

## 2.1.2 variable-length vectors
assert_equal "hello", Melos::Vec.parse_stream(StringIO.new("\x05hello"))
assert_raises(ArgumentError) { Melos::Vec.parse_stream(StringIO.new("\x40\x05hello")) } # length 5 in a 2-byte header
assert_raises(ArgumentError) { Melos::Vec.parse_stream(StringIO.new("\x05hel")) }       # shorter than its length
assert_raises(ArgumentError) { Melos::Vec.parse_stream(StringIO.new("\x40")) }          # header cut short
assert_raises(ArgumentError) { Melos::Vec.parse_stream(StringIO.new("")) }
assert_raises(ArgumentError) { Melos::Vec.parse_stream(StringIO.new("\xC0\x00\x00\x00")) } # prefix 3
puts "[pass] non-minimal, truncated and invalid vector headers are rejected"

## 7.2 default capabilities list no default types
assert_empty Melos::Capabilities.new.proposals
assert_empty Melos::Capabilities.new.extensions
puts "[pass] default Capabilities list no default proposal or extension types"

alice_group, bob_group, alice, bob = two_member_group(suite_id)

## 6 / 10 version fields
message = alice_group.create_application_message("hi")
tampered = message.raw.dup
tampered[0, 2] = "\x00\x02"
assert_raises(ArgumentError) { bob_group.process_message(Melos::Struct::MLSMessage.new(tampered)) }
carol = Melos::Client.new(suite_id, identity: 'carol')
key_package_bytes = carol.create_key_package.message.raw.dup
key_package_bytes[0, 2] = "\x00\x02"
assert_raises(ArgumentError) { alice_group.create_add_proposal(Melos::Struct::MLSMessage.new(key_package_bytes)) }
puts "[pass] messages and KeyPackages with a version other than mls10 are rejected"

## 6.3.1 padding must be zero: make the sender pad with 0x01 bytes
util = Melos::Crypto::Util
util.singleton_class.alias_method(:zero_vector_for_real, :zero_vector)
util.define_singleton_method(:zero_vector) { |length| "\x01" * length }
begin
  bad_padding = alice_group.create_application_message("padded", padding_size: 8)
ensure
  util.singleton_class.alias_method(:zero_vector, :zero_vector_for_real)
end
assert_raises(ArgumentError) { bob_group.process_message(wire(bad_padding)) }
puts "[pass] a PrivateMessage with non-zero padding is rejected"

## 13.4 duplicate extensions
extension = Melos::Struct::Extension.create(extension_type: 0xF000, extension_data: "")
assert_raises(ArgumentError) { alice.create_group("dup", extensions: [extension, extension]) }
gce = Melos::Struct::GroupContextExtensions.create(extensions: [extension, extension])
proposal = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::GROUP_CONTEXT_EXTENSIONS, group_context_extensions: gce)
assert_raises(ArgumentError) { alice_group.create_commit(inline_proposals: [proposal]) }
puts "[pass] extension lists with a repeated type are rejected"

## 12.1.3 Remove of a blank leaf
proposal = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::REMOVE, remove: Melos::Struct::Remove.create(removed: 1))
proposal_blank = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::REMOVE, remove: Melos::Struct::Remove.create(removed: 5))
assert_raises(ArgumentError) { alice_group.create_commit(inline_proposals: [proposal_blank]) }
assert_raises(ArgumentError) { alice_group.create_commit(inline_proposals: [proposal, proposal]) } # the second one hits a blank leaf
puts "[pass] a Remove of a blank leaf, or the same leaf twice, is rejected"

## 12.2 a commit must not remove its own sender
self_remove = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::REMOVE, remove: Melos::Struct::Remove.create(removed: 0))
assert_raises(ArgumentError) { alice_group.create_commit(inline_proposals: [self_remove]) }
puts "[pass] a commit removing its own sender is rejected"

## 12.1.4 psk_nonce length
alice.add_external_psk("k", "secret")
bob.add_external_psk("k", "secret")
short_nonce = Melos::Struct::PreSharedKey.create(psk: Melos::Struct::PreSharedKeyID.create_external(psk_id: "k", psk_nonce: "abc"))
proposal = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::PSK, psk: short_nonce)
assert_raises(ArgumentError) { alice_group.create_commit(inline_proposals: [proposal]) }
puts "[pass] a PreSharedKey proposal with a nonce of the wrong length is rejected"

## 12.2 / 13.2 unknown proposal type
proposal = Melos::Struct::Proposal.create(proposal_type: 0x0042)
assert_raises(ArgumentError) { alice_group.create_commit(inline_proposals: [proposal]) }
puts "[pass] a proposal of an unknown type is rejected"

## 12.4 commit before sending application data; the group still works afterwards
bob_group.process_message(wire(alice_group.create_psk_proposal("k")))
assert_raises(ArgumentError) { bob_group.create_application_message("too early") }
result = alice_group.create_commit
bob_group.process_message(wire(result.commit))
alice_group.merge_commit(result.staged)
authenticated_content = alice_group.process_message(wire(bob_group.create_application_message("now")))
assert_equal "now", authenticated_content.content.application_data
puts "[pass] application data is refused while proposals are pending, and flows again after the commit"

## 12.4.2 a member removed by a commit cannot follow the group further
result = alice_group.create_commit(inline_proposals: [Melos::Struct::Proposal.create(proposal_type: C::ProposalType::REMOVE, remove: Melos::Struct::Remove.create(removed: 1))])
bob_group.process_message(wire(result.commit))
alice_group.merge_commit(result.staged)
assert_equal false, bob_group.active?
assert_equal true, alice_group.active?
assert_raises(ArgumentError) { bob_group.create_application_message("hello?") }
assert_raises(ArgumentError) { bob_group.process_message(wire(alice_group.create_psk_proposal("k"))) }
puts "[pass] a removed member becomes inactive"
