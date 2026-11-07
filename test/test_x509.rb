require 'minitest'
require 'melos'
require 'openssl'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

# X.509 credentials (RFC 9420 5.3, 5.3.1, 13.3) with Melos::Credential::X509 as the Authentication
# Service. The certificates are generated here: a root CA, and end-entity certificates whose public
# keys are the members' MLS signature keys.

def wire(message)
  Melos::Struct::MLSMessage.new(message.raw)
end

def deliver(group, message)
  group.process_message(wire(message))
end

def certificate(subject, public_key, issuer_key, issuer: nil, ca: false, not_before: Time.now - 60, not_after: Time.now + 3600, serial: rand(1 << 64))
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = serial
  cert.subject = OpenSSL::X509::Name.parse("/CN=#{subject}")
  cert.issuer = issuer ? issuer.subject : cert.subject
  cert.public_key = public_key
  cert.not_before = not_before
  cert.not_after = not_after
  extensions = OpenSSL::X509::ExtensionFactory.new
  extensions.subject_certificate = cert
  extensions.issuer_certificate = issuer || cert
  cert.add_extension(extensions.create_extension('basicConstraints', ca ? 'CA:TRUE' : 'CA:FALSE', true))
  cert.add_extension(extensions.create_extension('keyUsage', ca ? 'keyCertSign,cRLSign' : 'digitalSignature', true))
  cert.sign(issuer_key, OpenSSL::Digest.new('SHA256'))
  cert
end

C = Melos::Constants

ca_key = OpenSSL::PKey::EC.generate('prime256v1')
ca = certificate('melos test CA', ca_key, ca_key, ca: true, not_before: Time.now - 86_400, not_after: Time.now + 86_400)
other_ca_key = OpenSSL::PKey::EC.generate('prime256v1')
other_ca = certificate('another CA', other_ca_key, other_ca_key, ca: true)
store = OpenSSL::X509::Store.new
store.add_cert(ca)

suite_ids = ENV['TEST_ALL'] ? [1, 2, 3, 5, 7] : [1, 2]

suite_ids.each do |suite_id|
  puts "cipher suite #{suite_id}:"
  suite = Melos::Crypto::CipherSuite.new(suite_id)
  # a client whose credential is a certificate for its signature key, issued by issuer_key
  x509_client = lambda do |name, issuer: ca, issuer_key: ca_key, key: Melos::Crypto.generate_signature_key_pair(suite), certified_key: key, **cert_options|
    cert = certificate(name, certified_key, issuer_key, issuer: issuer, **cert_options)
    Melos::Client.new(suite_id, credential: Melos::Credential::X509.create_credential([cert]),
                                signature_private_key: Melos::Crypto.serialize_private_key(suite, key))
  end
  validator = Melos::Credential::X509.new(store: store)

  alice = x509_client.('alice')
  bob = x509_client.('bob')
  assert_equal [C::CredentialType::BASIC, C::CredentialType::X509], bob.create_key_package.key_package.leaf_node.capabilities.export.credentials
  assert_equal Melos::Credential::X509.signature_key_bytes(Melos::Credential::X509.certificates(alice.credential).first.public_key), alice.signature_public_key

  ## a group of X.509 members, each checking the others' certificates
  alice_group = alice.create_group("x509-#{suite_id}", credential_validator: validator)
  alice_group.create_add_proposal(wire(bob.create_key_package.message))
  result = alice_group.create_commit
  bob_group = bob.join_group(wire(result.welcome), credential_validator: validator)
  alice_group.merge_commit(result.staged)
  assert_equal alice_group.epoch_authenticator, bob_group.epoch_authenticator
  assert_equal "certified", deliver(alice_group, bob_group.create_application_message("certified")).content.application_data
  result = bob_group.create_commit
  deliver(alice_group, result.commit)
  bob_group.merge_commit(result.staged)
  assert_equal alice_group.epoch_authenticator, bob_group.epoch_authenticator
  puts "[pass] members with X.509 credentials form a group and commit"

  ## an intermediate CA, sent in the chain
  intermediate_key = OpenSSL::PKey::EC.generate('prime256v1')
  intermediate = certificate('intermediate', intermediate_key, ca_key, issuer: ca, ca: true)
  carol_key = Melos::Crypto.generate_signature_key_pair(suite)
  carol_cert = certificate('carol', carol_key, intermediate_key, issuer: intermediate)
  carol = Melos::Client.new(suite_id, credential: Melos::Credential::X509.create_credential([carol_cert, intermediate]),
                                      signature_private_key: Melos::Crypto.serialize_private_key(suite, carol_key))
  deliver(bob_group, alice_group.create_add_proposal(wire(carol.create_key_package.message)))
  result = alice_group.create_commit
  deliver(bob_group, result.commit)
  alice_group.merge_commit(result.staged)
  carol_group = carol.join_group(wire(result.welcome), credential_validator: validator)
  assert_equal alice_group.epoch_authenticator, carol_group.epoch_authenticator
  puts "[pass] a chain through an intermediate verifies"

  ## rejections, as the sender of an Add
  add = ->(client) { alice_group.create_add_proposal(wire(client.create_key_package.message)) }
  # a certificate for a different key than the leaf's signature key (5.3)
  mismatched = x509_client.('mallory', certified_key: Melos::Crypto.generate_signature_key_pair(suite))
  refute validator.call(mismatched.credential, mismatched.create_key_package.key_package.leaf_node)
  assert_match(/key differs/, validator.last_error)
  assert_raises(Melos::ProtocolError) { add.(mismatched) }
  # a certificate from an untrusted CA, and an expired one
  assert_raises(Melos::ProtocolError) { add.(x509_client.('stranger', issuer: other_ca, issuer_key: other_ca_key)) }
  expired = x509_client.('expired', not_before: Time.now - 7200, not_after: Time.now - 3600)
  refute validator.call(expired.credential, expired.create_key_package.key_package.leaf_node)
  assert_match(/expired/, validator.last_error)
  assert_raises(Melos::ProtocolError) { add.(expired) }
  # ... which a validator set to a time inside its validity accepts (5.3.2, messages from the past)
  assert Melos::Credential::X509.new(store: store, time: Time.now - 5400).call(expired.credential, expired.create_key_package.key_package.leaf_node)
  # a basic credential, unless allowed; such a client must also list X.509 to join this group (13.3)
  dave = Melos::Client.new(suite_id, identity: 'dave', credential_types: [C::CredentialType::BASIC, C::CredentialType::X509])
  assert_raises(Melos::ProtocolError) { add.(dave) }
  lenient = Melos::Credential::X509.new(store: store, accept_basic: true)
  assert lenient.call(dave.credential, dave.create_key_package.key_package.leaf_node)
  # a client that does not support X.509 credentials cannot join a group that uses them
  erin = Melos::Client.new(suite_id, identity: 'erin')
  assert_equal [C::CredentialType::BASIC], erin.create_key_package.key_package.leaf_node.capabilities.export.credentials
  assert_raises(Melos::ProtocolError) { Melos::Group.from_h(alice_group.to_h, credential_validator: lenient).create_add_proposal(wire(erin.create_key_package.message)) }
  # the application's identity check (5.3.1)
  picky = Melos::Credential::X509.new(store: store, identity_check: ->(cert, _holder) { cert.subject.to_s == '/CN=alice' })
  assert picky.call(alice.credential, alice_group.ratchet_tree.leaf_node_at(0))
  refute picky.call(bob.credential, alice_group.ratchet_tree.leaf_node_at(1))
  puts "[pass] mismatched keys, untrusted and expired certificates, basic credentials and unsupported types are rejected"

  ## 5.3.1: an external sender's credential is validated when the external_senders extension is set
  trusted_key = Melos::Crypto.generate_signature_key_pair(suite)
  trusted = Melos::ExternalSender.new(suite_id, credential: Melos::Credential::X509.create_credential([certificate('ds', trusted_key, ca_key, issuer: ca)]),
                                                signature_private_key: Melos::Crypto.serialize_private_key(suite, trusted_key))
  untrusted_key = Melos::Crypto.generate_signature_key_pair(suite)
  untrusted = Melos::ExternalSender.new(suite_id, credential: Melos::Credential::X509.create_credential([certificate('ds', untrusted_key, other_ca_key, issuer: other_ca)]),
                                                  signature_private_key: Melos::Crypto.serialize_private_key(suite, untrusted_key))
  gce = ->(sender) {
    Melos::Struct::Proposal.create(proposal_type: C::ProposalType::GROUP_CONTEXT_EXTENSIONS,
                                   group_context_extensions: Melos::Struct::GroupContextExtensions.create(extensions: [Melos::Struct::ExternalSenders.extension([sender.external_sender])]))
  }
  assert_raises(Melos::ProtocolError) { alice_group.create_commit(inline_proposals: [gce.(untrusted)]) }
  result = alice_group.create_commit(inline_proposals: [gce.(trusted)])
  [bob_group, carol_group].each { deliver(_1, result.commit) }
  alice_group.merge_commit(result.staged)
  assert_equal alice_group.epoch_authenticator, carol_group.epoch_authenticator
  remove = trusted.create_remove_proposal(2, group_id: alice_group.group_id, epoch: alice_group.epoch, sender_index: 0)
  [alice_group, bob_group, carol_group].each { deliver(_1, remove) }
  result = bob_group.create_commit
  [alice_group, carol_group].each { deliver(_1, result.commit) }
  bob_group.merge_commit(result.staged)
  assert_equal false, carol_group.active?
  puts "[pass] external senders' credentials are validated; a certified external sender removes a member"
end
