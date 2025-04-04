require 'openssl'
require 'hpke'
require_relative 'vec_base'

module MLS; end

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
    end

    module P256
      def self.deserialize_private_key(secret)
        asn1_seq = OpenSSL::ASN1.Sequence([
          OpenSSL::ASN1.Integer(1),
          OpenSSL::ASN1.OctetString(secret),
          OpenSSL::ASN1.ObjectId('prime256v1', 0, :EXPLICIT)
        ])

        OpenSSL::PKey.read(asn1_seq.to_der)
      end

      def self.deserialize_public_key(serialized_pk)
        asn1_seq = OpenSSL::ASN1.Sequence([
          OpenSSL::ASN1.Sequence([
            OpenSSL::ASN1.ObjectId("id-ecPublicKey"),
            OpenSSL::ASN1.ObjectId('prime256v1')
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
      end
    end
  end

  module Util
    def self.zero_vector(length)
      ([0] * length).pack('C*')
    end
  end

  # DIGEST = OpenSSL::Digest::SHA256
  # DIGEST_INSTANCE = OpenSSL::Digest.new('sha256')
  # KDF = HPKE::HKDF.new(:sha256)
  # HPKE = HPKE.new(:x25519, :sha256, :sha256, :aes_128_gcm)

  def self.ref_hash(suite, label, value)
    ref_hash_input = label.to_vec + value.to_vec
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

  def self.kdf_n_h(suite)
    suite.kdf.n_h
  end

  def self.expand_with_label(suite, secret, label, context, length)
    kdf_label = [length].pack('S>') + ("MLS 1.0 " + label).to_vec + context.to_vec
    suite.kdf.expand(secret, kdf_label, length)
  end

  def self.derive_secret(suite, secret, label)
    expand_with_label(suite, secret, label, "", suite.kdf.n_h)
  end

  def self.derive_tree_secret(suite, secret, label, generation, length)
    generation_in_uint32 = [generation].pack('L>')
    expand_with_label(suite, secret, label, generation_in_uint32, length)
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
    encrypt_context = ("MLS 1.0 " + label).to_vec + context.to_vec
    pkey = suite.pkey.deserialize_public_encapsulation_key(public_key)
    seal_base(suite, pkey, encrypt_context, "", plaintext)
  end

  def self.decrypt_with_label(suite, private_key, label, context, kem_output, ciphertext)
    encrypt_context = ("MLS 1.0 " + label).to_vec + context.to_vec
    pkey = suite.pkey.deserialize_private_encapsulation_key(private_key)
    open_base(suite, kem_output, pkey, encrypt_context, "", ciphertext)
  end

  def self.sign_with_label(suite, signature_key, label, content)
    skey = suite.pkey.deserialize_private_signing_key(signature_key)
    sign_content = ("MLS 1.0 " + label).to_vec + content.to_vec
    skey.sign(nil, sign_content)
  end

  def self.verify_with_label(suite, verification_key, label, content, signature_value)
    vkey = suite.pkey.deserialize_public_signing_key(verification_key)
    sign_content = ("MLS 1.0 " + label).to_vec + content.to_vec
    vkey.verify(nil, signature_value, sign_content)
  end

  def self.mac(suite, key, data)
    OpenSSL::HMAC.digest(suite.digest, key, data)
  end

  def self.hash(suite, data)
    suite.digest.digest(data)
  end

  def self.aead_n_n
    HPKE.n_n
  end

  def self.aead_n_k
    HPKE.n_k
  end

  ## TODO: implement this in HPKE gem
  def self.aead_encrypt(key, nonce, aad, plaintext)
    cipher = OpenSSL::Cipher.new('aes-128-gcm')
    cipher.encrypt
    cipher.key = key
    cipher.iv = nonce
    cipher.auth_data = aad
    cipher.padding = 0
    s = cipher.update(pt) << cipher.final
    s += cipher.auth_tag
  end

  def self.aead_decrypt(key, nonce, aad, ciphertext)
    ct_body = ciphertext[0, ciphertext.length - HPKE.n_t]
    tag = ciphertext[-HPKE.n_t, HPKE.n_t]
    cipher = OpenSSL::Cipher.new('aes-128-gcm')
    cipher.decrypt
    cipher.key = key
    cipher.iv = nonce
    cipher.auth_tag = tag
    cipher.auth_data = aad
    cipher.padding = 0
    cipher.update(ct_body) << cipher.final
  end
end
