require 'minitest'
require 'melos'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

# External proposals (RFC 9420 12.1.8, 12.1.8.1, 6.1): a sender listed in the external_senders
# extension, and a client proposing its own Add as a new_member_proposal.

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
    assert_equal a.epoch_authenticator, b.epoch_authenticator
    assert_equal a.ratchet_tree.raw, b.ratchet_tree.raw
  end
end

C = Melos::Constants

suite_ids = ENV['TEST_ALL'] ? [1, 2, 3, 4, 5, 6, 7] : [1, 2]

suite_ids.each do |suite_id|
  puts "cipher suite #{suite_id}:"
  server = Melos::ExternalSender.new(suite_id, identity: 'server')
  stranger = Melos::ExternalSender.new(suite_id, identity: 'stranger') # not in the extension

  alice = Melos::Client.new(suite_id, identity: 'alice')
  bob = Melos::Client.new(suite_id, identity: 'bob')
  carol = Melos::Client.new(suite_id, identity: 'carol')

  extensions = [Melos::Struct::ExternalSenders.extension([server.external_sender])]
  alice_group = alice.create_group("external-#{suite_id}", extensions: extensions)
  alice_group.create_add_proposal(wire(bob.create_key_package.message))
  result = alice_group.create_commit
  bob_group = bob.join_group(wire(result.welcome))
  alice_group.merge_commit(result.staged)
  assert_equal [server.signature_public_key], bob_group.external_senders.map(&:signature_key)
  puts "[pass] the external_senders extension reaches a joiner"

  at = -> { { group_id: alice_group.group_id, epoch: alice_group.epoch, sender_index: 0 } }

  ## the server adds Carol; Bob commits the external proposal; Carol joins
  add_carol = server.create_add_proposal(carol.create_key_package.message, **at.())
  assert_nil add_carol.public_message.membership_tag
  [alice_group, bob_group].each do |group|
    authenticated_content = deliver(group, add_carol)
    assert_equal C::SenderType::EXTERNAL, authenticated_content.content.sender.sender_type
  end
  result = bob_group.create_commit
  deliver(alice_group, result.commit)
  bob_group.merge_commit(result.staged)
  carol_group = carol.join_group(wire(result.welcome))
  assert_same_epoch(alice_group, bob_group, carol_group)
  puts "[pass] an external sender's Add is committed and the new member joins"

  ## the server removes Bob; Alice commits it
  remove_bob = server.create_remove_proposal(1, **at.())
  [alice_group, bob_group, carol_group].each { deliver(_1, remove_bob) }
  commit_and_deliver(alice_group, bob_group, carol_group)
  assert_same_epoch(alice_group, carol_group)
  assert_equal false, bob_group.active?
  assert_nil alice_group.ratchet_tree.leaf_node_at(1)
  puts "[pass] an external sender removes a member"

  ## a non-member asks to join with its own Add (new_member_proposal); Carol commits it
  dave = Melos::Client.new(suite_id, identity: 'dave')
  request, _bundle = dave.create_new_member_proposal(group_id: alice_group.group_id, epoch: alice_group.epoch)
  assert_equal C::SenderType::NEW_MEMBER_PROPOSAL, request.public_message.content.sender.sender_type
  [alice_group, carol_group].each { deliver(_1, request) }
  result = carol_group.create_commit
  deliver(alice_group, result.commit)
  carol_group.merge_commit(result.staged)
  dave_group = dave.join_group(wire(result.welcome))
  assert_same_epoch(alice_group, carol_group, dave_group)
  puts "[pass] a non-member's own Add is committed and it joins"

  ## rejections
  # 12.1.8: an Update is not a proposal type an external sender may send
  leaf = alice_group.ratchet_tree.leaf_node_at(0)
  update = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::UPDATE, update: Melos::Struct::Update.create(leaf_node: leaf))
  assert_raises(ArgumentError) { server.create_proposal(update, **at.()) }
  forged = Melos::ExternalSender.sign_proposal(server.suite, server.signature_private_key, update, Melos::Struct::Sender.create_external(0),
                                               group_id: alice_group.group_id, epoch: alice_group.epoch)
  assert_raises(Melos::ProtocolError) { deliver(alice_group, forged) }
  # a sender index beyond the extension, and a signer that is not the one at the index
  assert_raises(Melos::ProtocolError) { deliver(alice_group, server.create_remove_proposal(2, **at.().merge(sender_index: 1))) }
  assert_raises(Melos::ProtocolError) { deliver(alice_group, stranger.create_remove_proposal(2, **at.())) }
  # a new member may only propose an Add
  remove = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::REMOVE, remove: Melos::Struct::Remove.create(removed: 2))
  bad_request = Melos::ExternalSender.sign_proposal(
    alice_group.suite, dave.signature_private_key, remove, Melos::Struct::Sender.create_new_member(C::SenderType::NEW_MEMBER_PROPOSAL),
    group_id: alice_group.group_id, epoch: alice_group.epoch
  )
  assert_raises(Melos::ProtocolError) { deliver(alice_group, bad_request) }
  # an external proposal for an old epoch
  assert_raises(Melos::ProtocolError) { deliver(alice_group, server.create_remove_proposal(2, **at.().merge(epoch: alice_group.epoch - 1))) }
  # the application's authorization hook (12.1.8)
  erin = Melos::Client.new(suite_id, identity: 'erin')
  strict = alice.create_group("strict-#{suite_id}", external_proposal_validator: ->(_) { false })
  request, _ = erin.create_new_member_proposal(group_id: strict.group_id, epoch: strict.epoch)
  assert_raises(Melos::ProtocolError) { deliver(strict, request) }
  # without the external_senders extension, no external sender is accepted
  remove_any = server.create_remove_proposal(0, group_id: strict.group_id, epoch: strict.epoch, sender_index: 0)
  assert_raises(Melos::ProtocolError) { deliver(strict, remove_any) }
  # the group is unaffected by all of the above
  commit_and_deliver(alice_group, carol_group, dave_group)
  assert_same_epoch(alice_group, carol_group, dave_group)
  puts "[pass] external Updates, unknown or wrong signers, non-Add new-member proposals, stale epochs and unauthorized proposals are rejected"
end
