class Melos::KeyPackage
  attr_reader :cipher_suite, :client
  attr_accessor :signature_key_pair, :encryption_key_pair, :init_key_pair
  
  def initialize(client)
    @cipher_suite = client.cipher_suite
    @client = client
    @init_key_pair = Melos::Crypto.generate_encapsulation_key_pair(@cipher_suite)
  end

  def create_leaf_node(credential_name = '', custom_capabilities = nil, custom_lifetime = nil)
    ln = Melos::Struct::LeafNode.create(
      encryption_key: @client.encryption_public_key,
      signature_key: @client.signature_public_key,
      credential: Melos::Struct::Credential.create_basic_credential(credential_name),
      capabilities: custom_capabilities ? custom_capabilities : Melos::Struct::Capabilities.import(Melos::Capabilities.new),
      leaf_node_source: Melos::Constants::LeafNodeSource::KEY_PACKAGE,
      lifetime: custom_lifetime ? custom_lifetime : Melos::Struct::Lifetime.create(not_before: Time.now.to_i, not_after: Time.now.to_i + 60 * 60 * 24 * 7),
      parent_hash: nil,
      extensions: [],
      signature: nil
    )
    # When LeafNodeSource is KEY_PACKAGE, group_id and leaf_index are not used
    ln.sign(@cipher_suite, @client.signature_private_key, nil, nil)
    ln
  end

  def create_message(leaf_node)
    kpm = Melos::Struct::KeyPackage.create(
      cipher_suite: @cipher_suite.suite_id,
      init_key: init_public_key,
      leaf_node: leaf_node
    )
    kpm.sign(@client.signature_private_key)
    kpm
  end

  def init_public_key
    @cipher_suite.pkey.serialize_public_key(@init_key_pair)
  end
  
  def init_private_key
    @cipher_suite.pkey.serialize_private_key(@init_key_pair)
  end
end