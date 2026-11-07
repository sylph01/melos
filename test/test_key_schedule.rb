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

  # before the first epoch only init_secret is known
  epoch_secrets = Melos::EpochSecrets.from_init_secret(suite, from_hex(key_schedule_vector['initial_init_secret']))

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
    psk_secret = from_hex(epoch['psk_secret'])
    # advance the key schedule: joiner_secret from init_secret and commit_secret, then epoch_secret
    epoch_secrets = epoch_secrets.next(commit_secret, psk_secret, group_context)

    assert_equal epoch['joiner_secret'], to_hex(epoch_secrets.joiner_secret)
    puts "[s] joiner_secret"

    assert_equal epoch['welcome_secret'], to_hex(epoch_secrets.welcome_secret)
    puts "[s] welcome_secret"

    # Secrets from epoch_secret
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
      assert_equal from_hex(epoch[secret_name]), epoch_secrets.send(secret_name.to_sym)
      puts "[s] #{secret_name}"
    end

    # 8.3: the external key pair comes from external_secret
    assert_equal epoch['external_pub'], to_hex(Melos::Crypto.external_key_pair(suite, epoch_secrets.external_secret)[1])
    puts "[s] external_pub"

    # Next Init Secret
    assert_equal epoch['init_secret'], to_hex(epoch_secrets.init_secret)
    puts "[s] init_secret"
    puts "[s] Epoch #{n}"
  end
end
