require_relative 'tree'
require_relative 'crypto'

module MLS; end

module MLS::SecretTree
  def self.sender_data_key(suite, sender_data_secret, ciphertext)
    ciphertext_sample = ciphertext[0..(suite.kdf.n_h - 1)]
    MLS::Crypto.expand_with_label(suite, sender_data_secret, "key", ciphertext_sample, suite.hpke.n_k)
  end

  def self.sender_data_nonce(suite, sender_data_secret, ciphertext)
    ciphertext_sample = ciphertext[0..(suite.kdf.n_h - 1)]
    MLS::Crypto.expand_with_label(suite, sender_data_secret, "nonce", ciphertext_sample, suite.hpke.n_n)
  end

  def self.populate_tree(suite, tree, root_secret)
    populate_tree_impl(suite, tree, tree.root, root_secret)
  end

  def self.populate_tree_impl(suite, tree, index, secret)
    tree.array[index] = {
      'handshake_ratchet_secret' => MLS::Crypto.expand_with_label(suite, secret, "handshake",   "", suite.kdf.n_h),
      'application_ratchet_secret' => MLS::Crypto.expand_with_label(suite, secret, "application", "", suite.kdf.n_h),
      'handshake_ratchet_secret_generation' => 0,
      'application_ratchet_secret_generation' => 0
    }
    unless MLS::Tree.leaf?(index)
      left_secret  = MLS::Crypto.expand_with_label(suite, secret, "tree", "left", suite.kdf.n_h)
      right_secret = MLS::Crypto.expand_with_label(suite, secret, "tree", "right", suite.kdf.n_h)
      populate_tree_impl(suite, tree, MLS::Tree.left(index), left_secret)
      populate_tree_impl(suite, tree, MLS::Tree.right(index), right_secret)
    end
  end

  def self.ratchet_application(suite, tree, leaf_index)
    node_index = leaf_index * 2
    generation = tree.array[node_index]['application_ratchet_secret_generation']
    application_ratchet_secret = tree.array[node_index]['application_ratchet_secret']
    application_nonce = MLS::Crypto.derive_tree_secret(suite, application_ratchet_secret, "nonce", generation, suite.hpke.n_n)
    application_key   = MLS::Crypto.derive_tree_secret(suite, application_ratchet_secret, "key",   generation, suite.hpke.n_k)
    next_application_ratchet_secret = MLS::Crypto.derive_tree_secret(suite, application_ratchet_secret, "secret", generation, suite.kdf.n_h)
    tree.array[node_index]['application_ratchet_secret_generation'] = generation + 1
    tree.array[node_index]['application_ratchet_secret'] = next_application_ratchet_secret
    tree.array[node_index]['application_nonce'] = application_nonce
    tree.array[node_index]['application_key']   = application_key
  end

  def self.ratchet_handshake(suite, tree, leaf_index)
    node_index = leaf_index * 2
    generation = tree.array[node_index]['handshake_ratchet_secret_generation']
    handshake_ratchet_secret = tree.array[node_index]['handshake_ratchet_secret']
    handshake_nonce = MLS::Crypto.derive_tree_secret(suite, handshake_ratchet_secret, "nonce", generation, suite.hpke.n_n)
    handshake_key   = MLS::Crypto.derive_tree_secret(suite, handshake_ratchet_secret, "key",   generation, suite.hpke.n_k)
    next_handshake_ratchet_secret = MLS::Crypto.derive_tree_secret(suite, handshake_ratchet_secret, "secret", generation, suite.kdf.n_h)
    tree.array[node_index]['handshake_ratchet_secret_generation'] = generation + 1
    tree.array[node_index]['handshake_ratchet_secret'] = next_handshake_ratchet_secret
    tree.array[node_index]['handshake_nonce'] = handshake_nonce
    tree.array[node_index]['handshake_key']   = handshake_key
  end
end
