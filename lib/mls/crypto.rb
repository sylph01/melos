require 'openssl'
require 'hpke'
require_relative 'vec'

class MLS::Crypto
  class CipherSuite
    module X25519
      def self.deserialize_public_encapsulation_key(raw)
        OpenSSL::PKey.new_raw_public_key('X25519', raw)
      end

      def self.deserialize_private_encapsulation_key(raw)
        OpenSSL::PKey.new_raw_private_key('X25519', raw)
      end

      def self.deserialize_public_signing_key(raw)
        OpenSSL::PKey.new_raw_public_key('ED25519', raw)
      end

      def self.deserialize_private_signing_key(raw)
        OpenSSL::PKey.new_raw_private_key('ED25519', raw)
      end

      def self.hash_algorithm
        nil
      end
    end

    module X448
      def self.deserialize_public_encapsulation_key(raw)
        OpenSSL::PKey.new_raw_public_key('X448', raw)
      end

      def self.deserialize_private_encapsulation_key(raw)
        OpenSSL::PKey.new_raw_private_key('X448', raw)
      end

      def self.deserialize_public_signing_key(raw)
        OpenSSL::PKey.new_raw_public_key('ED448', raw)
      end

      def self.deserialize_private_signing_key(raw)
        OpenSSL::PKey.new_raw_private_key('ED448', raw)
      end

      def self.hash_algorithm
        nil
      end
    end

    class EC
      # also would like to depend on HPKE gem...
      def self.deserialize_private_key(secret)
        asn1_seq = OpenSSL::ASN1.Sequence([
          OpenSSL::ASN1.Integer(1),
          OpenSSL::ASN1.OctetString(secret),
          OpenSSL::ASN1.ObjectId(curve_name, 0, :EXPLICIT)
        ])

        OpenSSL::PKey.read(asn1_seq.to_der)
      end

      def self.deserialize_public_key(serialized_pk)
        asn1_seq = OpenSSL::ASN1.Sequence([
          OpenSSL::ASN1.Sequence([
            OpenSSL::ASN1.ObjectId("id-ecPublicKey"),
            OpenSSL::ASN1.ObjectId(curve_name)
          ]),
          OpenSSL::ASN1.BitString(serialized_pk)
        ])

        OpenSSL::PKey.read(asn1_seq.to_der)
      end

      def self.deserialize_private_encapsulation_key(raw)
        self.deserialize_private_key(raw)
      end
      def self.deserialize_private_signing_key(raw)
        self.deserialize_private_key(raw)
      end
      def self.deserialize_public_encapsulation_key(raw)
        self.deserialize_public_key(raw)
      end
      def self.deserialize_public_signing_key(raw)
        self.deserialize_public_key(raw)
      end
    end

    class P256 < EC
      def self.curve_name
        'prime256v1'
      end

      def self.hash_algorithm
        'sha256'
      end
    end

    class P384 < EC
      def self.curve_name
        'secp384r1'
      end

      def self.hash_algorithm
        'sha384'
      end
    end

    class P521 < EC
      def self.curve_name
        'secp521r1'
      end

      def self.hash_algorithm
        'sha512'
      end
    end

    attr_accessor :level, :digest, :hpke, :kdf, :pkey
    def initialize(suite_id)
      case suite_id
      when 1 # MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        @level = 128
        @digest = OpenSSL::Digest.new('sha256')
        @hpke = HPKE.new(:x25519, :sha256, :sha256, :aes_128_gcm)
        @kdf = @hpke.hkdf
        @pkey = MLS::Crypto::CipherSuite::X25519
      when 2 # MLS_128_DHKEMP256_AES128GCM_SHA256_P256
        @level = 128
        @digest = OpenSSL::Digest.new('sha256')
        @hpke = HPKE.new(:p_256, :sha256, :sha256, :aes_128_gcm)
        @kdf = @hpke.hkdf
        @pkey = MLS::Crypto::CipherSuite::P256
      when 3 # MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        @level = 128
        @digest = OpenSSL::Digest.new('sha256')
        @hpke = HPKE.new(:x25519, :sha256, :sha256, :chacha20_poly1305)
        @kdf = @hpke.hkdf
        @pkey = MLS::Crypto::CipherSuite::X25519
      when 4 # MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        @level = 256
        @digest = OpenSSL::Digest.new('sha512')
        @hpke = HPKE.new(:x448, :sha512, :sha512, :aes_256_gcm)
        @kdf = @hpke.hkdf
        @pkey = MLS::Crypto::CipherSuite::X448
      when 5 # MLS_256_DHKEMP521_AES256GCM_SHA512_P521
        @level = 256
        @digest = OpenSSL::Digest.new('sha512')
        @hpke = HPKE.new(:p_521, :sha512, :sha512, :aes_256_gcm)
        @kdf = @hpke.hkdf
        @pkey = MLS::Crypto::CipherSuite::P521
      when 6 # MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
        @level = 256
        @digest = OpenSSL::Digest.new('sha512')
        @hpke = HPKE.new(:x448, :sha512, :sha512, :chacha20_poly1305)
        @kdf = @hpke.hkdf
        @pkey = MLS::Crypto::CipherSuite::X448
      when 7 # MLS_256_DHKEMP384_AES256GCM_SHA384_P384
        @level = 256
        @digest = OpenSSL::Digest.new('sha384')
        @hpke = HPKE.new(:p_384, :sha384, :sha384, :aes_256_gcm)
        @kdf = @hpke.hkdf
        @pkey = MLS::Crypto::CipherSuite::P384
      end
    end
  end

  module Util
    def self.zero_vector(length)
      ([0] * length).pack('C*')
    end
  end

  def self.ref_hash(suite, label, value)
    ref_hash_input = MLS::Vec.from_string(label) + MLS::Vec.from_string(value)
    suite.digest.digest(ref_hash_input)
  end

  def self.make_keypackage_ref(suite, value)
    self.ref_hash(suite, "MLS 1.0 KeyPackage Reference", value)
  end

  def self.make_proposal_ref(suite, value)
    self.ref_hash(suite, "MLS 1.0 Proposal Reference", value)
  end

  def self.kdf_extract(suite, salt, ikm)
    suite.kdf.extract(salt, ikm)
  end

  def self.expand_with_label(suite, secret, label, context, length)
    kdf_label = [length].pack('S>') + MLS::Vec.from_string("MLS 1.0 " + label) + MLS::Vec.from_string(context)
    suite.kdf.expand(secret, kdf_label, length)
  end

  def self.derive_secret(suite, secret, label)
    expand_with_label(suite, secret, label, "", suite.kdf.n_h)
  end

  def self.derive_tree_secret(suite, secret, label, generation, length)
    generation_in_uint32 = [generation].pack('L>')
    expand_with_label(suite, secret, label, generation_in_uint32, length)
  end

  def self.derive_key_pair(suite, secret)
    pkey = suite.hpke.kem.derive_key_pair(secret)
    if suite.pkey.equal?(MLS::Crypto::CipherSuite::X25519) || suite.pkey.equal?(MLS::Crypto::CipherSuite::X448)
      # is an Edwards curve
      [pkey.raw_private_key, pkey.raw_public_key]
    else
      # is an EC
      [pkey.private_key.to_s(2), pkey.public_key.to_bn.to_s(2)]
    end
  end

  def self.seal_base(suite, pkr, info, aad, pt)
    context = suite.hpke.setup_base_s(pkr, info)
    enc = context[:enc]
    ctx = context[:context_s]
    ct = ctx.seal(aad, pt)
    [enc, ct]
  end

  def self.open_base(suite, enc, skr, info, aad, ct)
    ctx = suite.hpke.setup_base_r(enc, skr, info)
    ctx.open(aad, ct)
  end

  def self.encrypt_with_label(suite, public_key, label, context, plaintext)
    encrypt_context = MLS::Vec.from_string("MLS 1.0 " + label) + MLS::Vec.from_string(context)
    pkey = suite.pkey.deserialize_public_encapsulation_key(public_key)
    seal_base(suite, pkey, encrypt_context, "", plaintext)
  end

  def self.decrypt_with_label(suite, private_key, label, context, kem_output, ciphertext)
    encrypt_context = MLS::Vec.from_string("MLS 1.0 " + label) + MLS::Vec.from_string(context)
    pkey = suite.pkey.deserialize_private_encapsulation_key(private_key)
    open_base(suite, kem_output, pkey, encrypt_context, "", ciphertext)
  end

  def self.sign_with_label(suite, signature_key, label, content)
    skey = suite.pkey.deserialize_private_signing_key(signature_key)
    sign_content = MLS::Vec.from_string("MLS 1.0 " + label) + MLS::Vec.from_string(content)
    skey.sign(suite.pkey.hash_algorithm, sign_content)
  end

  def self.verify_with_label(suite, verification_key, label, content, signature_value)
    vkey = suite.pkey.deserialize_public_signing_key(verification_key)
    sign_content = MLS::Vec.from_string("MLS 1.0 " + label) + MLS::Vec.from_string(content)
    vkey.verify(suite.pkey.hash_algorithm, signature_value, sign_content)
  end

  def self.mac(suite, key, data)
    OpenSSL::HMAC.digest(suite.digest, key, data)
  end

  def self.hash(suite, data)
    suite.digest.digest(data)
  end

  def self.aead_encrypt(suite, key, nonce, aad, plaintext)
    suite.hpke.aead_encrypt(key, nonce, aad, plaintext)
  end

  def self.aead_decrypt(suite, key, nonce, aad, ciphertext)
    suite.hpke.aead_decrypt(key, nonce, aad, ciphertext)
  end

  def self.sender_data_key(suite, sender_data_secret, ciphertext)
    ciphertext_sample = ciphertext[0..(suite.kdf.n_h - 1)]
    expand_with_label(suite, sender_data_secret, "key", ciphertext_sample, suite.hpke.n_k)
  end

  def self.sender_data_nonce(suite, sender_data_secret, ciphertext)
    ciphertext_sample = ciphertext[0..(suite.kdf.n_h - 1)]
    expand_with_label(suite, sender_data_secret, "nonce", ciphertext_sample, suite.hpke.n_n)
  end

  def self.encapsulation_key_pair_corresponds?(suite, private_key, public_key)
    private_pkey = suite.pkey.deserialize_private_encapsulation_key(private_key)
    public_pkey  = suite.pkey.deserialize_public_encapsulation_key(public_key)
    if suite.pkey.equal?(MLS::Crypto::CipherSuite::X25519) || suite.pkey.equal?(MLS::Crypto::CipherSuite::X448)
      # is an Edwards curve; check equality of the raw public key
      private_pkey.raw_public_key == public_pkey.raw_public_key
    else
      # is an EC; check equality of the public key Point
      private_pkey.public_key == public_pkey.public_key
    end
  end

  def self.parent_hash(suite, encryption_key, ph_of_parent, sibling_hash)
    parent_hash_input = MLS::Vec.from_string(encryption_key) + MLS::Vec.from_string(ph_of_parent) + MLS::Vec.from_string(sibling_hash)
    MLS::Crypto.hash(suite, parent_hash_input)
  end
end
