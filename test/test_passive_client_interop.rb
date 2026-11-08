require 'json'
require 'melos'
require 'minitest'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

# Passive client vectors recorded from live interop runs (mls-implementations interop/passive, at
# 2034fe7): a client joins by Welcome and follows the group's commits, which were produced by other
# implementations while running the interop configs (application, branch, commit, external_join,
# external_proposals, reinit, welcome_join). Same format as passive-client-*.json.
#
# Some vectors carry KeyPackages whose extensions include GREASE types (0x?A?A, RFC 9420 13.5) that the
# leaf's capabilities do not list. RFC 9420 10 requires every KeyPackage extension to be in the
# leaf's capabilities, so melos rejects those (as OpenMLS does; see cisco/mlspp#470). They are counted
# and must fail for exactly that reason; any other failure fails this test.

GREASE_REJECTION = /\AKeyPackage extensions not in its capabilities: 0x([0-9a-f])a\1a(, 0x([0-9a-f])a\3a)*\z/

Dir['test_vectors/interop-passive/*.json'].sort.each do |file|
  passed = 0
  grease = 0
  JSON.load_file(file).each_with_index do |vec, vec_index|
    suite = Melos::Crypto::CipherSuite.new(vec['cipher_suite'])
    begin
      group = Melos::Group.from_welcome(
        suite, Melos::Struct::MLSMessage.new(from_hex(vec['welcome'])),
        key_package: Melos::Struct::MLSMessage.new(from_hex(vec['key_package'])),
        init_private_key: from_hex(vec['init_priv']),
        encryption_private_key: from_hex(vec['encryption_priv']),
        signature_private_key: from_hex(vec['signature_priv']),
        external_psks: (vec['external_psks'] || []).to_h { [from_hex(_1['psk_id']), from_hex(_1['psk'])] },
        ratchet_tree: vec['ratchet_tree'] && from_hex(vec['ratchet_tree'])
      )
      assert_equal from_hex(vec['initial_epoch_authenticator']), group.epoch_authenticator, "#{file} ##{vec_index}: initial epoch authenticator"
      (vec['epochs'] || []).each_with_index do |epoch, epoch_index|
        epoch['proposals'].each { group.process_message(Melos::Struct::MLSMessage.new(from_hex(_1))) }
        group.process_message(Melos::Struct::MLSMessage.new(from_hex(epoch['commit'])))
        assert_equal from_hex(epoch['epoch_authenticator']), group.epoch_authenticator, "#{file} ##{vec_index}: epoch authenticator after commit #{epoch_index}"
      end
      passed += 1
    rescue Melos::ProtocolError => e
      raise unless e.message.match?(GREASE_REJECTION)
      grease += 1
    end
  end
  puts "[pass] #{File.basename(file)}: #{passed} vectors followed#{grease.positive? ? ", #{grease} rejected for unlisted GREASE KeyPackage extensions" : ''}"
end
