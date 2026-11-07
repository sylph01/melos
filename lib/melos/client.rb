require_relative 'crypto'
require_relative 'key_package_bundle'
require_relative 'group'
require_relative 'struct/structs'

# A client (RFC 9420 Section 5.3): a long-lived identity, i.e. a signature key pair and a
# credential, plus what a client keeps across groups: the external PSKs it knows (8.4) and the
# KeyPackages it has published and may still be welcomed into a group with (10).
class Melos::Client
  attr_reader :cipher_suite, :credential, :external_psks, :key_packages

  def initialize(cipher_suite_id, identity: '')
    @cipher_suite = Melos::Crypto::CipherSuite.new(cipher_suite_id)
    @signature_key_pair = Melos::Crypto.generate_signature_key_pair(@cipher_suite)
    @credential = Melos::Struct::Credential.create_basic_credential(identity)
    @external_psks = {} # psk_id -> psk; shared by reference with the groups this client is in
    @key_packages = {}  # KeyPackageRef -> Melos::KeyPackageBundle, until used to join a group
  end

  def signature_private_key
    Melos::Crypto.serialize_private_key(@cipher_suite, @signature_key_pair)
  end

  def signature_public_key
    Melos::Crypto.serialize_public_key(@cipher_suite, @signature_key_pair)
  end

  # 8.4: an external PSK that commits in this client's groups may reference
  def add_external_psk(psk_id, psk)
    @external_psks[psk_id] = psk
  end

  # 10: publish a KeyPackage. The bundle is kept so that a Welcome addressed to it can be processed.
  def create_key_package(capabilities: nil, lifetime: nil, extensions: [])
    bundle = Melos::KeyPackageBundle.generate(
      @cipher_suite, signature_private_key: signature_private_key, signature_public_key: signature_public_key,
      credential: @credential, capabilities: capabilities, lifetime: lifetime, extensions: extensions
    )
    @key_packages[bundle.ref] = bundle
    bundle
  end

  # 11: create a group with this client as its only member
  def create_group(group_id, extensions: [])
    bundle = Melos::KeyPackageBundle.generate(
      @cipher_suite, signature_private_key: signature_private_key, signature_public_key: signature_public_key, credential: @credential
    )
    Melos::Group.create(
      @cipher_suite, group_id, bundle.key_package.leaf_node,
      encryption_private_key: bundle.encryption_private_key, signature_private_key: signature_private_key,
      extensions: extensions, external_psks: @external_psks
    )
  end

  # 12.4.3.1: join the group a Welcome adds us to, using whichever of our KeyPackages it is addressed to.
  # That KeyPackage is then forgotten: its init key is single-use.
  def join_group(welcome, ratchet_tree: nil)
    welcome_struct = welcome.is_a?(Melos::Struct::MLSMessage) ? welcome.welcome : welcome
    raise ArgumentError.new('not a Welcome message') if welcome_struct.nil?
    bundle = welcome_struct.secrets.map(&:new_member).filter_map { @key_packages[_1] }.first
    raise ArgumentError.new('Welcome is not addressed to any KeyPackage of this client') if bundle.nil?
    group = Melos::Group.from_welcome(
      @cipher_suite, welcome,
      key_package: bundle.key_package, init_private_key: bundle.init_private_key,
      encryption_private_key: bundle.encryption_private_key, signature_private_key: signature_private_key,
      external_psks: @external_psks, ratchet_tree: ratchet_tree
    )
    @key_packages.delete(bundle.ref)
    group
  end
end
