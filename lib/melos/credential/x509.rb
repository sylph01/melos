require 'openssl'
require_relative '../constants'
require_relative '../struct/structs'

module Melos::Credential; end

# X.509 credentials (RFC 9420 5.3, 5.3.1): building them, and an Authentication Service check that a
# group can use as its credential_validator:
#
#   validator = Melos::Credential::X509.new(store: store) # an OpenSSL::X509::Store with the trusted roots
#   client.create_group(group_id, credential_validator: validator)
#
# For a leaf (or external sender) with an X.509 credential, it checks that the end-entity certificate's
# public key is the holder's signature_key (5.3), that the chain verifies against the store at the
# given time (the current time by default; this covers validity dates), and, if given, the
# application's identity check: which presented identifiers it accepts for this member (5.3.1).
# Whether a new credential is a valid successor of the one it replaces is also the application's call,
# through that check. Basic credentials are rejected unless accept_basic: is true.
class Melos::Credential::X509
  attr_reader :last_error

  # certificates: the chain, end-entity first, as OpenSSL::X509::Certificate or DER strings
  def self.create_credential(certificates)
    Melos::Struct::Credential.create(
      credential_type: Melos::Constants::CredentialType::X509, identity: nil,
      certificates: certificates.map { Melos::Struct::Certificate.create(cert_data: _1.is_a?(OpenSSL::X509::Certificate) ? _1.to_der : _1) }
    )
  end

  # the certificates of an X.509 credential, end-entity first
  def self.certificates(credential)
    credential.certificates.map { OpenSSL::X509::Certificate.new(_1.cert_data) }
  end

  # a public key as MLS encodes a SignaturePublicKey: the raw key for Ed25519 and Ed448, the
  # uncompressed point for ECDSA
  def self.signature_key_bytes(public_key)
    if public_key.is_a?(OpenSSL::PKey::EC)
      public_key.public_key.to_bn.to_s(2)
    else
      public_key.raw_public_key
    end
  end

  #   store: OpenSSL::X509::Store holding the trust anchors (and any intermediates peers may omit)
  #   time: the time to verify the chain at, or nil for now
  #   identity_check: ->(end_entity_certificate, holder) { true/false }, the application's reference identifiers
  #   accept_basic: whether basic credentials pass (they carry nothing to check)
  def initialize(store:, time: nil, identity_check: nil, accept_basic: false)
    @store = store
    @time = time
    @identity_check = identity_check
    @accept_basic = accept_basic
    @last_error = nil
  end

  # the credential_validator interface: holder is the LeafNode or ExternalSender carrying the credential
  def call(credential, holder)
    validate!(credential, holder)
    @last_error = nil
    true
  rescue Melos::ProtocolError, OpenSSL::X509::CertificateError, OpenSSL::PKey::PKeyError => e
    @last_error = e.message
    false
  end

  # like #call, but raises Melos::ProtocolError with the reason
  def validate!(credential, holder)
    case credential.credential_type
    when Melos::Constants::CredentialType::BASIC
      return if @accept_basic
      raise Melos::ProtocolError.new('basic credentials are not accepted')
    when Melos::Constants::CredentialType::X509
      certificates = self.class.certificates(credential)
      raise Melos::ProtocolError.new('X.509 credential has no certificates') if certificates.empty?
      end_entity, *chain = certificates
      # 5.3: the end-entity certificate's key is the holder's signature key
      unless self.class.signature_key_bytes(end_entity.public_key) == holder.signature_key
        raise Melos::ProtocolError.new('end-entity certificate key differs from the signature key')
      end
      context = OpenSSL::X509::StoreContext.new(@store, end_entity, chain)
      context.time = @time if @time
      raise Melos::ProtocolError.new("certificate chain does not verify: #{context.error_string}") unless context.verify
      if @identity_check && !@identity_check.call(end_entity, holder)
        raise Melos::ProtocolError.new('certificate identity not accepted for this member')
      end
    else
      raise Melos::ProtocolError.new("unsupported credential type #{credential.credential_type}")
    end
  end
end
