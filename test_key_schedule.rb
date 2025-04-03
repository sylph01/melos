require 'json'
require 'minitest'
require_relative 'structs.rb'
require_relative 'crypto'
require_relative 'vec_base'
include Minitest::Assertions

class << self
attr_accessor :assertions
end
self.assertions = 0

key_schedule_vectors = JSON.parse(File.read('test_vectors/key-schedule.json'))
key_schedule_vector = key_schedule_vectors[0]

init_secret = from_hex(key_schedule_vector['initial_init_secret'])

key_schedule_vector['epochs'].each_with_index do |epoch, n|
  commit_secret = from_hex(epoch['commit_secret'])
  group_context = MLSStruct::GroupContext.create(
    cipher_suite: 1,
    group_id: from_hex(key_schedule_vector['group_id']),
    epoch: n,
    tree_hash: from_hex(epoch['tree_hash']),
    confirmed_transcript_hash: from_hex(epoch['confirmed_transcript_hash']),
    extensions: []
  )
  # puts to_hex(group_context.raw)
  # puts epoch['group_context']
  joiner_secret = MLS::Crypto.expand_with_label(
    MLS::Crypto.kdf_extract(init_secret, commit_secret),
    "joiner",
    group_context.raw,
    MLS::Crypto.kdf_n_h
  )
  assert_equal to_hex(joiner_secret), epoch['joiner_secret']
  puts "[s] joiner_secret"

  # Welcome Secret
  member_secret = MLS::Crypto.kdf_extract(joiner_secret, from_hex(epoch['psk_secret']))
  welcome_secret = MLS::Crypto.derive_secret(member_secret, "welcome")
  assert_equal to_hex(welcome_secret), epoch['welcome_secret']
  puts "[s] welcome_secret"

  # Secrets from epoch_secret
  epoch_secret = MLS::Crypto.expand_with_label(member_secret, "epoch", group_context.raw, MLS::Crypto.kdf_n_h)

  secrets = {}
  [
    ['sender data', 'sender_data_secret'],
    ['encryption',  'encryption_secret'],
    ['exporter',    'exporter_secret'],
    ['external',    'external_secret'],
    ['confirm',     'confirmation_key'],
    ['membership',  'membership_key'],
    ['resumption',  'resumption_psk'],
    ['authentication', 'epoch_authenticator']
  ].each do |tuple|
    label = tuple[0]
    name  = tuple[1]

    secrets[name] = MLS::Crypto.derive_secret(epoch_secret, label)
    assert_equal to_hex(secrets[name]), epoch[name]
    puts "[s] #{name}"
  end

  # Next Init Secret
  init_secret = MLS::Crypto.derive_secret(epoch_secret, "init")
  assert_equal to_hex(init_secret), epoch['init_secret']
  puts "[s] init_secret"
  puts "[s] Epoch #{n}"
end
