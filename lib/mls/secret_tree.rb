require_relative 'tree'
require_relative 'crypto'

module MLS::SecretTree
  def self.create(suite, n_leaves, encryption_secret)
    st = MLS::Tree.empty_tree(n_leaves)
    populate_tree(suite, st, encryption_secret)
    st
  end

  def self.populate_tree(suite, tree, root_secret)
    populate_tree_impl(suite, tree, tree.root, root_secret)
  end

  def self.populate_tree_impl(suite, tree, index, secret)
    tree.array[index] = {
      'handshake_ratchet_secret' => MLS::Crypto.expand_with_label(suite, secret, "handshake",   "", suite.kdf.n_h),
      'application_ratchet_secret' => MLS::Crypto.expand_with_label(suite, secret, "application", "", suite.kdf.n_h),
      'next_handshake_ratchet_secret_generation' => 0,
      'next_application_ratchet_secret_generation' => 0
    }
    unless MLS::Tree.leaf?(index)
      left_secret  = MLS::Crypto.expand_with_label(suite, secret, "tree", "left", suite.kdf.n_h)
      right_secret = MLS::Crypto.expand_with_label(suite, secret, "tree", "right", suite.kdf.n_h)
      populate_tree_impl(suite, tree, MLS::Tree.left(index), left_secret)
      populate_tree_impl(suite, tree, MLS::Tree.right(index), right_secret)
    end
  end

  def self.ratchet_until_and_get(suite, content_type, tree, leaf_index, generation)
    # TODO: clear the value on tree when getting
    case content_type
    when 0x02, 0x03
      ratchet_handshake_until(suite, tree, leaf_index, generation)
      [
        tree.leaf_at(leaf_index)['handshake_key'],
        tree.leaf_at(leaf_index)['handshake_nonce'],
        generation
      ]
    else
      ratchet_application_until(suite, tree, leaf_index, generation)
      [
        tree.leaf_at(leaf_index)['application_key'],
        tree.leaf_at(leaf_index)['application_nonce'],
        generation
      ]
    end
  end

  def self.ratchet_and_get(suite, content_type, tree, leaf_index)
    # TODO: clear the value on tree when getting
    case content_type
    when 0x02, 0x03
      ratchet_handshake(suite, tree, leaf_index)
      [
        tree.leaf_at(leaf_index)['handshake_key'],
        tree.leaf_at(leaf_index)['handshake_nonce'],
        tree.leaf_at(leaf_index)['next_handshake_ratchet_secret_generation'] - 1, # returns current generation
      ]
    else
      ratchet_application(suite, tree, leaf_index)
      [
        tree.leaf_at(leaf_index)['application_key'],
        tree.leaf_at(leaf_index)['application_nonce'],
        tree.leaf_at(leaf_index)['next_application_ratchet_secret_generation'] - 1, # returns current generation
      ]
    end
  end

  def self.ratchet_application_until(suite, tree, leaf_index, generation)
    while (tree.leaf_at(leaf_index)['next_application_ratchet_secret_generation'] <= generation)
      ratchet_application(suite, tree, leaf_index)
    end
  end

  def self.ratchet_handshake_until(suite, tree, leaf_index, generation)
    raise ArgumentError.new('cannot generate past generation') if generation < tree.leaf_at(leaf_index)['next_handshake_ratchet_secret_generation'] - 1
    # if current generation, do nothing
    while (tree.leaf_at(leaf_index)['next_handshake_ratchet_secret_generation'] <= generation)
      ratchet_handshake(suite, tree, leaf_index)
    end
  end

  def self.ratchet_application(suite, tree, leaf_index)
    node_index = leaf_index * 2
    generation = tree.array[node_index]['next_application_ratchet_secret_generation']
    application_ratchet_secret = tree.array[node_index]['application_ratchet_secret']
    application_nonce = MLS::Crypto.derive_tree_secret(suite, application_ratchet_secret, "nonce", generation, suite.hpke.n_n)
    application_key   = MLS::Crypto.derive_tree_secret(suite, application_ratchet_secret, "key",   generation, suite.hpke.n_k)
    next_application_ratchet_secret = MLS::Crypto.derive_tree_secret(suite, application_ratchet_secret, "secret", generation, suite.kdf.n_h)
    tree.array[node_index]['next_application_ratchet_secret_generation'] = generation + 1
    tree.array[node_index]['application_ratchet_secret'] = next_application_ratchet_secret
    tree.array[node_index]['application_nonce'] = application_nonce
    tree.array[node_index]['application_key']   = application_key
  end

  def self.ratchet_handshake(suite, tree, leaf_index)
    node_index = leaf_index * 2
    generation = tree.array[node_index]['next_handshake_ratchet_secret_generation']
    handshake_ratchet_secret = tree.array[node_index]['handshake_ratchet_secret']
    handshake_nonce = MLS::Crypto.derive_tree_secret(suite, handshake_ratchet_secret, "nonce", generation, suite.hpke.n_n)
    handshake_key   = MLS::Crypto.derive_tree_secret(suite, handshake_ratchet_secret, "key",   generation, suite.hpke.n_k)
    next_handshake_ratchet_secret = MLS::Crypto.derive_tree_secret(suite, handshake_ratchet_secret, "secret", generation, suite.kdf.n_h)
    tree.array[node_index]['next_handshake_ratchet_secret_generation'] = generation + 1
    tree.array[node_index]['handshake_ratchet_secret'] = next_handshake_ratchet_secret
    tree.array[node_index]['handshake_nonce'] = handshake_nonce
    tree.array[node_index]['handshake_key']   = handshake_key
  end
end
