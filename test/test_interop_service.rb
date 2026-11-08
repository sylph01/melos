require 'minitest'
require 'melos'
include Minitest::Assertions

class << self
attr_accessor :assertions
end
self.assertions = 0

# The interop gRPC service (interop/melos_interop.rb), driven in-process the way the mls-implementations
# test runner drives it: requests in, responses out, handles between calls. The runner itself runs it
# over the network (interop/run.rb); this keeps the service covered by rake test.
begin
  require_relative '../interop/melos_interop'
rescue LoadError => e
  puts "[skip] interop service: #{e.message} (bundle install --with interop)"
  return
end

M = MlsClient
service = Melos::Interop::Service.new(log: nil)
call = ->(rpc, request) { service.public_send(rpc, request, nil) }

[1, 2].each do |suite|
  [false, true].each do |encrypt|
    puts "cipher suite #{suite}, #{encrypt ? 'private' : 'public'} handshakes:"
    alice = call.(:create_group, M::CreateGroupRequest.new(group_id: "interop-#{suite}-#{encrypt}", cipher_suite: suite, encrypt_handshake: encrypt, identity: 'alice')).state_id

    # createGroup with members: inline Adds, HandlePendingCommit, JoinGroup
    kp = call.(:create_key_package, M::CreateKeyPackageRequest.new(cipher_suite: suite, identity: 'bob'))
    commit = call.(:commit, M::CommitRequest.new(state_id: alice, by_value: [M::ProposalDescription.new(proposal_type: 'add', key_package: kp.key_package)]))
    refute_empty commit.welcome
    auth = call.(:handle_pending_commit, M::HandlePendingCommitRequest.new(state_id: alice)).epoch_authenticator
    bob = call.(:join_group, M::JoinGroupRequest.new(transaction_id: kp.transaction_id, welcome: commit.welcome, encrypt_handshake: encrypt, identity: 'bob'))
    assert_equal auth, bob.epoch_authenticator
    bob = bob.state_id
    puts "[pass] create, add by value, join"

    # protect / unprotect
    ciphertext = call.(:protect, M::ProtectRequest.new(state_id: bob, authenticated_data: 'ad', plaintext: 'hi')).ciphertext
    clear = call.(:unprotect, M::UnprotectRequest.new(state_id: alice, ciphertext: ciphertext))
    assert_equal ['ad', 'hi'], [clear.authenticated_data, clear.plaintext]

    # fullCommit with an Update by reference, passed back to its own sender too
    update = call.(:update_proposal, M::UpdateProposalRequest.new(state_id: bob)).proposal
    commit = call.(:commit, M::CommitRequest.new(state_id: alice, by_reference: [update], force_path: true))
    auth = call.(:handle_pending_commit, M::HandlePendingCommitRequest.new(state_id: alice)).epoch_authenticator
    assert_equal auth, call.(:handle_commit, M::HandleCommitRequest.new(state_id: bob, proposal: [update], commit: commit.commit)).epoch_authenticator
    puts "[pass] protect/unprotect, an Update committed by reference"

    # external join with the tree out of band, then a Remove by identity
    info = call.(:group_info, M::GroupInfoRequest.new(state_id: alice, external_tree: true))
    refute_empty info.ratchet_tree
    carol = call.(:external_join, M::ExternalJoinRequest.new(group_info: info.group_info, ratchet_tree: info.ratchet_tree, encrypt_handshake: encrypt, identity: 'carol'))
    [alice, bob].each do |member|
      assert_equal carol.epoch_authenticator, call.(:handle_commit, M::HandleCommitRequest.new(state_id: member, commit: carol.commit)).epoch_authenticator
    end
    remove = call.(:remove_proposal, M::RemoveProposalRequest.new(state_id: carol.state_id, removed_id: 'bob')).proposal
    commit = call.(:commit, M::CommitRequest.new(state_id: alice, by_reference: [remove]))
    auth = call.(:handle_pending_commit, M::HandlePendingCommitRequest.new(state_id: alice)).epoch_authenticator
    assert_equal auth, call.(:handle_commit, M::HandleCommitRequest.new(state_id: carol.state_id, proposal: [remove], commit: commit.commit)).epoch_authenticator
    puts "[pass] external join, Remove by identity"

    # errors come back as gRPC statuses
    assert_raises(GRPC::Aborted) { call.(:protect, M::ProtectRequest.new(state_id: 9999, plaintext: 'x')) }
    assert_raises(GRPC::Aborted) { call.(:remove_proposal, M::RemoveProposalRequest.new(state_id: alice, removed_id: 'nobody')) }
    puts "[pass] failures are gRPC Aborted statuses"
  end
end
