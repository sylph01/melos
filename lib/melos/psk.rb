require_relative 'crypto'

module Melos::PSK
  extend self

  # input: array of {psk_id: (raw PSK id), psk: (raw PSK value)}
  def psk_secret(suite, psk_array)
    secret = Melos::Crypto::Util.zero_vector(suite.kdf.n_h)

    psk_array.each_with_index do |psk, idx|
      psk_id = Melos::Struct::PreSharedKeyID.new(psk[:psk_id])
      psk_label = Melos::Struct::PSKLabel.create(
        id: psk_id,
        index: idx,
        count: psk_array.count
      )

      extracted = Melos::Crypto.kdf_extract(
        suite,
        Melos::Crypto::Util.zero_vector(suite.kdf.n_h),
        psk[:psk]
      )
      input = Melos::Crypto.expand_with_label(
        suite,
        extracted,
        "derived psk",
        psk_label.raw,
        suite.kdf.n_h
      )
      secret = Melos::Crypto.kdf_extract(suite, input, secret)
    end

    return secret
  end
end
