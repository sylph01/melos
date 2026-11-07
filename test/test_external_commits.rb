require 'minitest'
require 'melos'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

# External commits (RFC 9420 12.4.3.2, 8.3, 12.1.6, 12.2): a new member joins from a GroupInfo with an
# external_pub extension, and a member who lost its state rejoins with a "resync" commit.

def wire(message)
  Melos::Struct::MLSMessage.new(message.raw)
end

def deliver(group, message)
  group.process_message(wire(message))
end

def commit_and_deliver(committer, *others)
  result = committer.create_commit
  others.each { deliver(_1, result.commit) }
  committer.merge_commit(result.staged)
  result
end

def assert_same_epoch(*groups)
  groups.each_cons(2) do |a, b|
    assert_equal a.epoch, b.epoch
    assert_equal a.epoch_authenticator, b.epoch_authenticator
    assert_equal a.group_context.raw, b.group_context.raw
    assert_equal a.ratchet_tree.raw, b.ratchet_tree.raw
  end
end

# re-sign a FramedContent built from a genuine external commit, so that only what the test changes is wrong
def forge_external_commit(suite, signature_private_key, group, commit, confirmation_tag)
  framed_content = Melos::Struct::FramedContent.create(
    group_id: group.group_id, epoch: group.epoch, sender: Melos::Struct::Sender.create_new_member(Melos::Constants::SenderType::NEW_MEMBER_COMMIT),
    authenticated_data: '', content_type: Melos::Constants::ContentType::COMMIT, content: commit
  )
  authenticated_content = Melos::Struct::AuthenticatedContent.create(wire_format: Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE, content: framed_content, auth: nil)
  authenticated_content.sign(suite, signature_private_key, group.group_context, confirmation_tag: confirmation_tag)
  Melos::Struct::MLSMessage.create(public_message: Melos::Struct::PublicMessage.protect(authenticated_content, suite, nil, nil))
end

C = Melos::Constants

suite_ids = ENV['TEST_ALL'] ? [1, 2, 3, 4, 5, 6, 7] : [1, 2]

suite_ids.each do |suite_id|
  puts "cipher suite #{suite_id}:"
  suite = Melos::Crypto::CipherSuite.new(suite_id)
  alice = Melos::Client.new(suite_id, identity: 'alice')
  bob = Melos::Client.new(suite_id, identity: 'bob')
  alice_group = alice.create_group("external-commit-#{suite_id}")
  alice_group.create_add_proposal(wire(bob.create_key_package.message))
  result = alice_group.create_commit
  bob_group = bob.join_group(wire(result.welcome))
  alice_group.merge_commit(result.staged)

  ## a GroupInfo with external_pub and the tree; Carol joins with it
  group_info = wire(bob_group.group_info)
  assert_equal C::WireFormat::MLS_GROUP_INFO, group_info.wire_format
  carol = Melos::Client.new(suite_id, identity: 'carol')
  carol_group, commit = carol.join_by_external_commit(group_info)
  assert_equal C::SenderType::NEW_MEMBER_COMMIT, commit.public_message.content.sender.sender_type
  assert_nil commit.public_message.membership_tag
  [alice_group, bob_group].each { deliver(_1, commit) }
  assert_same_epoch(alice_group, bob_group, carol_group)
  assert_equal 2, carol_group.leaf_index
  assert_equal true, carol_group.private_tree.consistent?(carol_group.ratchet_tree)
  assert_empty carol_group.past_epochs # nothing from before the join
  puts "[pass] Carol joins by external commit"

  ## everyone talks and commits afterwards
  assert_equal "hi Carol", deliver(carol_group, alice_group.create_application_message("hi Carol")).content.application_data
  assert_equal "hi all", deliver(bob_group, carol_group.create_application_message("hi all")).content.application_data
  commit_and_deliver(carol_group, alice_group, bob_group)
  commit_and_deliver(bob_group, alice_group, carol_group)
  assert_same_epoch(alice_group, bob_group, carol_group)
  puts "[pass] the external joiner sends, receives and commits"

  ## with a PSK, and with the tree given out of band
  [alice, bob, carol].each { _1.add_external_psk("psk", "s" * 32) }
  dave = Melos::Client.new(suite_id, identity: 'dave')
  dave.add_external_psk("psk", "s" * 32)
  group_info = wire(alice_group.group_info(include_ratchet_tree: false))
  assert_raises(ArgumentError) { dave.join_by_external_commit(group_info) }
  dave_group, commit = dave.join_by_external_commit(group_info, ratchet_tree: alice_group.ratchet_tree.raw, psk_ids: ["psk"])
  [alice_group, bob_group, carol_group].each { deliver(_1, commit) }
  assert_same_epoch(alice_group, bob_group, carol_group, dave_group)
  puts "[pass] an external commit with a PSK, the tree given separately"

  ## Carol loses her state and rejoins, replacing her old leaf (resync)
  old_carol_group = carol_group
  new_carol = Melos::Client.new(suite_id, identity: 'carol')
  new_carol_group, commit = new_carol.join_by_external_commit(wire(bob_group.group_info), remove: 2)
  [alice_group, bob_group, dave_group, old_carol_group].each { deliver(_1, commit) }
  assert_same_epoch(alice_group, bob_group, dave_group, new_carol_group)
  assert_equal false, old_carol_group.active?
  assert_equal 2, new_carol_group.leaf_index
  # but only an earlier appearance of the same member may be removed this way
  erin = Melos::Client.new(suite_id, identity: 'erin')
  # (the joiner's own staging refuses it, with the check members run on receipt)
  assert_raises(Melos::ProtocolError) { erin.join_by_external_commit(wire(bob_group.group_info), remove: 1) }
  puts "[pass] a resync external commit replaces an old appearance; removing someone else is rejected"

  ## rejections
  # a GroupInfo of an earlier epoch
  stale_info = wire(alice_group.group_info)
  commit_and_deliver(alice_group, bob_group, new_carol_group, dave_group)
  _group, commit = Melos::Client.new(suite_id, identity: 'frank').join_by_external_commit(stale_info)
  assert_raises(Melos::ProtocolError) { deliver(bob_group, commit) }
  # a GroupInfo without external_pub
  assert_raises(Melos::ProtocolError) { erin.join_by_external_commit(wire(alice_group.group_info(external_pub: false))) }

  # forged variations of a genuine external commit by Grace
  grace = Melos::Client.new(suite_id, identity: 'grace')
  _group, genuine = grace.join_by_external_commit(wire(alice_group.group_info))
  genuine_commit = genuine.public_message.content.commit
  tag = genuine.public_message.auth.confirmation_tag
  forge = ->(proposals, path: genuine_commit.path) {
    forge_external_commit(suite, grace.signature_private_key, alice_group, Melos::Struct::Commit.create(proposals: proposals, path: path), tag)
  }
  by_value = ->(proposal) { Melos::Struct::ProposalOrRef.create(type: C::ProposalOrRefType::PROPOSAL, proposal: proposal, reference: nil) }
  external_init = genuine_commit.proposals.first
  # a proposal by reference (12.4.3.2)
  pending = bob_group.create_psk_proposal("psk")
  deliver(alice_group, pending)
  reference = Melos::Struct::ProposalOrRef.create(type: C::ProposalOrRefType::REFERENCE, proposal: nil,
                                                  reference: Melos::Crypto.make_proposal_ref(suite, alice_group.send(:unprotect, wire(pending)).raw))
  assert_raises(Melos::ProtocolError) { deliver(alice_group, forge.([external_init, reference])) }
  # no ExternalInit, two ExternalInits, an Add (12.2)
  assert_raises(Melos::ProtocolError) { deliver(alice_group, forge.([])) }
  assert_raises(Melos::ProtocolError) { deliver(alice_group, forge.([external_init, external_init])) }
  add = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::ADD, add: Melos::Struct::Add.create(key_package: erin.create_key_package.key_package))
  assert_raises(Melos::ProtocolError) { deliver(alice_group, forge.([external_init, by_value.(add)])) }
  # no path
  assert_raises(Melos::ProtocolError) { deliver(alice_group, forge.([external_init], path: nil)) }
  # an ExternalInit in a regular commit
  assert_raises(Melos::ProtocolError) { alice_group.create_commit(inline_proposals: [external_init.proposal]) }
  # the genuine one still goes through
  grace_group = grace.groups[alice_group.group_id]
  [alice_group, bob_group, new_carol_group, dave_group].each { deliver(_1, genuine) }
  assert_same_epoch(alice_group, bob_group, new_carol_group, dave_group, grace_group)
  puts "[pass] stale GroupInfos, missing external_pub, references, bad lists and missing paths are rejected"

  ## persistence keeps the confirmation tag, so a restored member can publish a GroupInfo
  restored = Melos::Group.from_h(alice_group.to_h)
  info = restored.group_info.group_info
  assert_equal true, info.verify(suite, alice_group.ratchet_tree.leaf_node_at(alice_group.leaf_index).signature_key)
  puts "[pass] a restored group publishes a GroupInfo"
end
