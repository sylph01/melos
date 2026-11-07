require 'minitest'
require 'melos'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

# Persistence of client and group state: members are saved and restored (through JSON) between
# every step, and messages sent before a restore are read after it. RFC 9420 6.3.1 is why this
# matters: a restored ratchet that went back would reuse nonces.

def wire(message)
  Melos::Struct::MLSMessage.new(message.raw)
end

# save and restore a client through JSON, and check the restored state is the same
def reload(client)
  json = Melos::Persistence.dump_client(client)
  restored = Melos::Persistence.load_client(json)
  assert_equal client.to_h, restored.to_h
  restored
end

def assert_same_epoch(a, b)
  assert_equal a.epoch, b.epoch
  assert_equal a.epoch_authenticator, b.epoch_authenticator
  assert_equal a.ratchet_tree.raw, b.ratchet_tree.raw
end

suite_ids = ENV['TEST_ALL'] ? [1, 2, 3, 4, 5, 6, 7] : [1, 2]

suite_ids.each do |suite_id|
  puts "cipher suite #{suite_id}:"
  group_id = "persisted-#{suite_id}"
  alice = Melos::Client.new(suite_id, identity: 'alice')
  bob = Melos::Client.new(suite_id, identity: 'bob')
  [alice, bob].each { _1.add_external_psk("psk", "k" * 32) }

  ## a published KeyPackage survives a restart
  key_package = bob.create_key_package
  bob = reload(bob)
  assert_equal [key_package.ref], bob.key_packages.keys
  alice.create_group(group_id)
  alice = reload(alice)
  alice.groups[group_id].create_add_proposal(wire(key_package.message))
  alice = reload(alice) # with the proposal pending
  result = alice.groups[group_id].create_commit
  alice.groups[group_id].merge_commit(result.staged)
  alice = reload(alice)
  bob.join_group(wire(result.welcome))
  bob = reload(bob)
  assert_same_epoch(alice.groups[group_id], bob.groups[group_id])
  assert_empty bob.key_packages
  puts "[pass] a KeyPackage kept across a restart is joined with"

  ## sending ratchets do not go back: messages before and after a restart both decrypt, once each
  first = alice.groups[group_id].create_application_message("before the restart")
  alice = reload(alice)
  second = alice.groups[group_id].create_application_message("after the restart")
  assert_equal "after the restart", bob.groups[group_id].process_message(wire(second)).content.application_data
  bob = reload(bob) # with generation 0 skipped and kept
  assert_equal "before the restart", bob.groups[group_id].process_message(wire(first)).content.application_data
  bob = reload(bob)
  assert_raises(Melos::StateError) { bob.groups[group_id].process_message(wire(first)) }
  assert_raises(Melos::StateError) { bob.groups[group_id].process_message(wire(second)) }
  puts "[pass] ratchet positions and skipped keys survive a restart"

  ## a pending Update survives on the proposer's side, a pending proposal on the committer's
  late = bob.groups[group_id].create_application_message("from the previous epoch")
  update = bob.groups[group_id].create_update_proposal
  bob = reload(bob)
  alice.groups[group_id].process_message(wire(update))
  psk_proposal = alice.groups[group_id].create_psk_proposal("psk")
  alice = reload(alice)
  bob.groups[group_id].process_message(wire(psk_proposal))
  bob = reload(bob)
  result = alice.groups[group_id].create_commit
  alice.groups[group_id].merge_commit(result.staged)
  alice = reload(alice)
  bob.groups[group_id].process_message(wire(result.commit))
  bob = reload(bob)
  assert_same_epoch(alice.groups[group_id], bob.groups[group_id])
  assert_equal true, bob.groups[group_id].private_tree.consistent?(bob.groups[group_id].ratchet_tree)
  puts "[pass] a pending Update and pending proposals survive a restart"

  ## a past epoch survives a restart
  assert_includes alice.groups[group_id].past_epochs, alice.groups[group_id].epoch - 1
  authenticated_content = alice.groups[group_id].process_message(wire(late))
  assert_equal "from the previous epoch", authenticated_content.content.application_data
  puts "[pass] an application message of the previous epoch decrypts after a restart"

  ## and the group goes on: a commit from Bob after his restart
  result = bob.groups[group_id].create_commit
  bob.groups[group_id].merge_commit(result.staged)
  bob = reload(bob)
  alice.groups[group_id].process_message(wire(result.commit))
  assert_same_epoch(alice.groups[group_id], bob.groups[group_id])
  # a resumption PSK of an earlier epoch is still there, and the external PSKs stay shared with the client
  assert_equal (0..alice.groups[group_id].epoch).to_a, alice.groups[group_id].resumption_psks.keys.sort
  alice.add_external_psk("later", "l" * 32)
  assert_equal "l" * 32, alice.groups[group_id].external_psks["later"]
  puts "[pass] restored members keep committing"

  ## a single group, saved on its own; and Marshal works on the Hash as it is
  group = alice.groups[group_id]
  restored = Melos::Persistence.load_group(Melos::Persistence.dump_group(group))
  assert_equal group.to_h, restored.to_h
  marshalled = Melos::Client.from_h(Marshal.load(Marshal.dump(bob.to_h)))
  assert_equal bob.to_h, marshalled.to_h
  # a restored group takes the application's hooks again
  strict = Melos::Group.from_h(group.to_h, credential_validator: ->(_credential, _leaf) { false })
  carol = Melos::Client.new(suite_id, identity: 'carol')
  assert_raises(Melos::ProtocolError) { strict.create_add_proposal(wire(carol.create_key_package.message)) }
  assert_raises(ArgumentError) { Melos::Group.from_h(group.to_h.merge(format: 99)) }
  puts "[pass] a group alone round-trips, Marshal works, hooks are passed again"
end
