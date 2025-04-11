require 'json'
require 'melos'
require 'minitest'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

if ENV['TEST_ALL']
  key_schedule_vectors = JSON.parse(File.read('test_vectors/key-schedule.json'))
else
  key_schedule_vectors = JSON.parse(File.read('test_vectors/key-schedule.json'))[0..0]
end

key_schedule_vectors = JSON.parse(File.read('test_vectors/key-schedule.json'))
key_schedule_vectors.each do |key_schedule_vector|
  suite = Melos::Crypto::CipherSuite.new(key_schedule_vector['cipher_suite'])
  puts "for cipher suite ID #{key_schedule_vector['cipher_suite']}:"

  init_secret = from_hex(key_schedule_vector['initial_init_secret'])

  key_schedule_vector['epochs'].each_with_index do |epoch, n|
    commit_secret = from_hex(epoch['commit_secret'])
    group_context = Melos::Struct::GroupContext.create(
      cipher_suite: key_schedule_vector['cipher_suite'],
      group_id: from_hex(key_schedule_vector['group_id']),
      epoch: n,
      tree_hash: from_hex(epoch['tree_hash']),
      confirmed_transcript_hash: from_hex(epoch['confirmed_transcript_hash']),
      extensions: []
    )
    # puts to_hex(group_context.raw)
    # puts epoch['group_context']
    joiner_secret = Melos::KeySchedule.joiner_secret(suite, init_secret, commit_secret, group_context)
    assert_equal to_hex(joiner_secret), epoch['joiner_secret']
    puts "[s] joiner_secret"

    # Welcome Secret
    psk_secret = from_hex(epoch['psk_secret'])
    welcome_secret = Melos::KeySchedule.welcome_secret(suite, joiner_secret, psk_secret)
    assert_equal to_hex(welcome_secret), epoch['welcome_secret']
    puts "[s] welcome_secret"

    # Secrets from epoch_secret
    epoch_secret = Melos::KeySchedule.epoch_secret(suite, joiner_secret, psk_secret, group_context)

    # secrets = {}
    [
      'sender_data_secret',
      'encryption_secret',
      'exporter_secret',
      'external_secret',
      'confirmation_key',
      'membership_key',
      'resumption_psk',
      'epoch_authenticator'
    ].each do |secret_name|
      assert_equal Melos::KeySchedule.send(secret_name.to_sym, suite, epoch_secret), from_hex(epoch[secret_name])
      puts "[s] #{secret_name}"
    end

    # Next Init Secret
    init_secret = Melos::KeySchedule.init_secret(suite, epoch_secret)
    assert_equal to_hex(init_secret), epoch['init_secret']
    puts "[s] init_secret"
    puts "[s] Epoch #{n}"
  end
end
