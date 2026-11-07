require 'minitest'
require 'melos'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

# Resumption PSKs (RFC 9420 8.6, 12.1.4), subgroup branching (11.3) and reinitialization (11.2, 12.1.5),
# with the joiner-side checks of 12.4.3.1.

def wire(message)
  Melos::Struct::MLSMessage.new(message.raw)
end

def deliver(group, message)
  group.process_message(wire(message))
end

def commit_and_deliver(committer, *others, **options)
  result = committer.create_commit(**options)
  others.each { deliver(_1, result.commit) }
  committer.merge_commit(result.staged)
  result
end

def assert_same_epoch(*groups)
  groups.each_cons(2) do |a, b|
    assert_equal a.epoch, b.epoch
    assert_equal a.epoch_authenticator, b.epoch_authenticator
    assert_equal a.ratchet_tree.raw, b.ratchet_tree.raw
  end
end

C = Melos::Constants

suite_pairs = ENV['TEST_ALL'] ? [[1, 1], [1, 2], [2, 3], [3, 7], [7, 5], [5, 6], [6, 4], [4, 1]] : [[1, 2], [2, 2]]

suite_pairs.each do |suite_id, new_suite_id|
  puts "cipher suite #{suite_id}, reinitialized to #{new_suite_id}:"
  group_id = "resumed-#{suite_id}-#{new_suite_id}"
  alice = Melos::Client.new(suite_id, identity: 'alice')
  bob = Melos::Client.new(suite_id, identity: 'bob')
  carol = Melos::Client.new(suite_id, identity: 'carol')

  alice_group = alice.create_group(group_id)
  alice_group.create_add_proposal(wire(bob.create_key_package.message))
  alice_group.create_add_proposal(wire(carol.create_key_package.message))
  result = alice_group.create_commit
  alice_group.merge_commit(result.staged)
  bob_group = bob.join_group(wire(result.welcome))
  carol_group = carol.join_group(wire(result.welcome))
  commit_and_deliver(bob_group, alice_group, carol_group)
  assert_same_epoch(alice_group, bob_group, carol_group)

  ## 8.6: a resumption PSK of an earlier epoch, usage application, injected by a PreSharedKey proposal
  proposal = carol_group.create_resumption_psk_proposal(1)
  assert_equal C::ResumptionPSKUsage::APPLICATION, proposal.public_message.content.proposal.psk.psk.usage
  [alice_group, bob_group].each { deliver(_1, proposal) }
  commit_and_deliver(carol_group, alice_group, bob_group)
  assert_same_epoch(alice_group, bob_group, carol_group)
  assert_raises(ArgumentError) { carol_group.create_resumption_psk_proposal(99) }
  puts "[pass] a resumption PSK of an earlier epoch is injected"

  ## 11.3: Alice branches a subgroup with Carol; Carol checks it against the group she is in
  branch, welcome = alice.branch_group(alice_group, [carol.create_key_package.message], group_id: "#{group_id}-branch")
  assert_equal 1, branch.epoch
  carol_branch = carol.join_group(wire(welcome))
  assert_same_epoch(branch, carol_branch)
  assert_equal 2, carol_branch.ratchet_tree.n_leaves
  assert_equal "hi", deliver(carol_branch, branch.create_application_message("hi")).content.application_data
  # the old group goes on alongside
  commit_and_deliver(alice_group, bob_group, carol_group)
  assert_same_epoch(alice_group, bob_group, carol_group)
  # a member outside the old group cannot be in a branch, on either side
  dave = Melos::Client.new(suite_id, identity: 'dave')
  assert_raises(ArgumentError) { alice.branch_group(alice_group, [dave.create_key_package.message], group_id: "#{group_id}-dave") }
  _forged, welcome = alice.send(:resume, alice_group, [carol.create_key_package.message, dave.create_key_package.message],
                                C::ResumptionPSKUsage::BRANCH, "#{group_id}-forged", [], {})
  assert_raises(Melos::ProtocolError) { carol.join_group(wire(welcome)) }
  puts "[pass] a subgroup is branched, and a branch with an outsider is rejected"

  ## a reinit Welcome for a group that was not reinitialized is rejected
  _forged, welcome = alice.send(:resume, alice_group, [bob.create_key_package.message], C::ResumptionPSKUsage::REINIT, "#{group_id}-not-reinit", [], {})
  assert_raises(Melos::ProtocolError) { bob.join_group(wire(welcome)) }
  # 11.2, 12.1.4: a resumption PSK with usage reinit or branch is invalid in an ordinary commit
  [C::ResumptionPSKUsage::REINIT, C::ResumptionPSKUsage::BRANCH].each do |usage|
    psk = Melos::Struct::PreSharedKeyID.create_resumption(usage: usage, psk_group_id: group_id, psk_epoch: alice_group.epoch, psk_nonce: "n" * alice_group.suite.kdf.n_h)
    proposal = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::PSK, psk: Melos::Struct::PreSharedKey.create(psk: psk))
    assert_raises(Melos::ProtocolError) { alice_group.create_commit(inline_proposals: [proposal]) }
    # and on the receiving side, for a committer that skipped the check
    alice_group.instance_variable_set(:@resumption_override, [psk.raw, alice_group.resumption_psks[alice_group.epoch]])
    result = alice_group.create_commit(inline_proposals: [proposal])
    alice_group.instance_variable_set(:@resumption_override, nil)
    assert_raises(Melos::ProtocolError) { deliver(bob_group, result.commit) }
  end
  # 12.2: a ReInit must be alone; reinit_group needs a committed ReInit
  reinit = Melos::Struct::Proposal.create(
    proposal_type: C::ProposalType::REINIT,
    reinit: Melos::Struct::ReInit.create(group_id: group_id, version: C::Version::MLS10, cipher_suite: suite_id, extensions: [])
  )
  remove = Melos::Struct::Proposal.create(proposal_type: C::ProposalType::REMOVE, remove: Melos::Struct::Remove.create(removed: 2))
  assert_raises(Melos::ProtocolError) { alice_group.create_commit(inline_proposals: [reinit, remove]) }
  assert_raises(Melos::StateError) { alice.reinit_group(alice_group, []) }
  puts "[pass] reinit Welcomes without a ReInit, reinit/branch PSK proposals and ReInits with company are rejected"

  ## 11.2: Bob proposes reinitializing to another cipher suite; Alice commits it; the group ends
  proposal = bob_group.create_reinit_proposal(cipher_suite: new_suite_id)
  [alice_group, carol_group].each { deliver(_1, proposal) }
  # with another proposal also pending, the committer leaves the ReInit for later (12.2)
  update = carol_group.create_update_proposal
  [alice_group, bob_group].each { deliver(_1, update) }
  result = commit_and_deliver(alice_group, bob_group, carol_group)
  assert_equal 1, result.commit.public_message.content.commit.proposals.size
  assert_equal true, alice_group.active?
  proposal = bob_group.create_reinit_proposal(cipher_suite: new_suite_id)
  [alice_group, carol_group].each { deliver(_1, proposal) }
  old_epoch = alice_group.epoch + 1
  commit_and_deliver(alice_group, bob_group, carol_group)
  [alice_group, bob_group, carol_group].each do |group|
    assert_equal false, group.active?
    assert_equal old_epoch, group.epoch
    assert_equal new_suite_id, group.pending_reinit.cipher_suite
    assert_raises(Melos::StateError) { group.create_application_message("still here?") }
  end
  puts "[pass] a committed ReInit ends the group"

  ## the new group: same members, new suite, epoch 1, resumption PSK of usage reinit
  clients = new_suite_id == suite_id ? [alice, bob, carol] : %w[alice bob carol].map { Melos::Client.new(new_suite_id, identity: _1) }
  new_alice, new_bob, new_carol = clients
  # a KeyPackage for every other member is needed
  assert_raises(ArgumentError) { new_alice.reinit_group(alice_group, [new_bob.create_key_package.message]) }
  new_group, welcome = new_alice.reinit_group(alice_group, [new_bob.create_key_package.message, new_carol.create_key_package.message])
  assert_equal 1, new_group.epoch
  assert_equal new_suite_id, new_group.suite.suite_id
  assert_equal group_id, new_group.group_id
  # without the old group at hand, the PSK cannot be found
  unless new_suite_id == suite_id
    assert_raises(Melos::StateError) { new_bob.join_group(wire(welcome)) }
  end
  new_bob_group = new_bob.join_group(wire(welcome), resumed_groups: [bob_group])
  new_carol_group = new_carol.join_group(wire(welcome), resumed_groups: [carol_group])
  assert_same_epoch(new_group, new_bob_group, new_carol_group)
  assert_equal "reinitialized", deliver(new_carol_group, new_bob_group.create_application_message("reinitialized")).content.application_data
  commit_and_deliver(new_carol_group, new_group, new_bob_group)
  assert_same_epoch(new_group, new_bob_group, new_carol_group)
  # the old group's resumption PSKs remain available to the client that replaced it
  if new_suite_id == suite_id
    assert_equal alice_group.resumption_psks[old_epoch], alice.resumption_psk(group_id, old_epoch)
    refute_same alice_group, alice.groups[group_id]
  end
  puts "[pass] the group is reinitialized with the same members and every member joins"

  ## and it all survives persistence
  restored = Melos::Persistence.load_client(Melos::Persistence.dump_client(new_alice))
  assert_equal new_alice.to_h, restored.to_h
  restored_old = Melos::Group.from_h(bob_group.to_h)
  assert_equal new_suite_id, restored_old.pending_reinit.cipher_suite
  puts "[pass] reinit state and archived resumption PSKs persist"
end
