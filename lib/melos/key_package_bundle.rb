require_relative 'crypto'
require_relative 'constants'
require_relative 'capabilities'
require_relative 'struct/structs'

# A KeyPackage this client has published (RFC 9420 Section 10), together with the private keys
# that belong to it: the init key, used once to decrypt the Welcome that adds us, and the leaf's
# encryption key, which becomes our leaf's private key in the group. Each KeyPackage has its own
# encryption key pair, so every leaf a client holds is keyed separately.
class Melos::KeyPackageBundle
  attr_reader :suite, :key_package, :init_private_key, :encryption_private_key

  DEFAULT_LIFETIME = 60 * 60 * 24 * 7 # seconds

  def initialize(suite, key_package, init_private_key, encryption_private_key)
    @suite = suite
    @key_package = key_package
    @init_private_key = init_private_key
    @encryption_private_key = encryption_private_key
  end

  # 10: a fresh KeyPackage signed with signature_private_key, whose leaf carries signature_public_key and credential
  def self.generate(suite, signature_private_key:, signature_public_key:, credential:, capabilities: nil, lifetime: nil, extensions: [])
    init_key_pair = Melos::Crypto.generate_encapsulation_key_pair(suite)
    encryption_key_pair = Melos::Crypto.generate_encapsulation_key_pair(suite)
    now = Time.now.to_i
    leaf_node = Melos::Struct::LeafNode.create(
      encryption_key: Melos::Crypto.serialize_public_key(suite, encryption_key_pair),
      signature_key: signature_public_key,
      credential: credential,
      capabilities: capabilities || Melos::Struct::Capabilities.import(Melos::Capabilities.new),
      leaf_node_source: Melos::Constants::LeafNodeSource::KEY_PACKAGE,
      lifetime: lifetime || Melos::Struct::Lifetime.create(not_before: now, not_after: now + DEFAULT_LIFETIME),
      parent_hash: nil,
      extensions: extensions,
      signature: nil
    )
    leaf_node.sign(suite, signature_private_key, nil, nil) # 7.2: group_id and leaf_index are not part of a key_package leaf's signature
    key_package = Melos::Struct::KeyPackage.create(
      cipher_suite: suite.suite_id,
      init_key: Melos::Crypto.serialize_public_key(suite, init_key_pair),
      leaf_node: leaf_node
    )
    key_package.sign(signature_private_key)
    new(suite, key_package,
        Melos::Crypto.serialize_private_key(suite, init_key_pair),
        Melos::Crypto.serialize_private_key(suite, encryption_key_pair))
  end

  def to_h
    { key_package: @key_package.raw, init_private_key: @init_private_key, encryption_private_key: @encryption_private_key }
  end

  def self.from_h(suite, hash)
    new(suite, Melos::Struct::KeyPackage.new(hash[:key_package]), hash[:init_private_key], hash[:encryption_private_key])
  end

  # 5.2: the KeyPackageRef a Welcome uses to address this KeyPackage
  def ref
    @key_package.ref(@suite)
  end

  # the KeyPackage as it is published: an MLSMessage
  def message
    Melos::Struct::MLSMessage.create(key_package: @key_package)
  end
end
