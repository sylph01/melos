require_relative 'crypto'

module Melos::KeySchedule
  extend self

  def joiner_secret(suite, init_secret, commit_secret, group_context)
    Melos::Crypto.expand_with_label(
      suite,
      Melos::Crypto.kdf_extract(suite, init_secret, commit_secret),
      "joiner",
      group_context.raw,
      suite.kdf.n_h
    )
  end

  def welcome_secret(suite, joiner_secret, psk_secret)
    Melos::Crypto.derive_secret(
      suite,
      Melos::Crypto.kdf_extract(suite, joiner_secret, psk_secret), # sometimes written as `member_secret`
      "welcome"
    )
  end

  def epoch_secret(suite, joiner_secret, psk_secret, group_context)
    Melos::Crypto.expand_with_label(
      suite,
      Melos::Crypto.kdf_extract(suite, joiner_secret, psk_secret),
      "epoch",
      group_context.raw,
      suite.kdf.n_h
    )
  end

  # epoch-derived secrets, from Table 4 in Section 8
  # will be defined as something like:
  # Melos::KeySchedule.sender_data_secret(suite, epoch_secret)
  [
    ['sender data', 'sender_data_secret'],
    ['encryption',  'encryption_secret'],
    ['exporter',    'exporter_secret'],
    ['external',    'external_secret'],
    ['confirm',     'confirmation_key'],
    ['membership',  'membership_key'],
    ['resumption',  'resumption_psk'],
    ['authentication', 'epoch_authenticator'],
    ['init', 'init_secret'] # this is not part of the table but is defined in the same way
  ].each do |tuple|
    label = tuple[0]
    name  = tuple[1]
    define_method(name.to_sym, ->(suite, epoch_secret){
      Melos::Crypto.derive_secret(suite, epoch_secret, label)
    })
  end
end
