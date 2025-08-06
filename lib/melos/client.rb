class Melos::Client
  attr_reader :cipher_suite
  attr_accessor :signature_key_pair, :encryption_key_pair

  def initialize(cipher_suite_id)
    @cipher_suite = Melos::Crypto::CipherSuite.new(cipher_suite_id)
    @signature_key_pair = Melos::Crypto.generate_signature_key_pair(@cipher_suite)
    @encryption_key_pair = Melos::Crypto.generate_encapsulation_key_pair(@cipher_suite)
  end

  def signature_private_key
    @cipher_suite.pkey.serialize_private_key(@signature_key_pair)
  end

  def signature_public_key
    @cipher_suite.pkey.serialize_public_key(@signature_key_pair)
  end

  def encryption_private_key
    @cipher_suite.pkey.serialize_private_key(@encryption_key_pair)
  end

  def encryption_public_key
    @cipher_suite.pkey.serialize_public_key(@encryption_key_pair)
  end

  # TODO: need a way to marshal/unmarshal safely
end