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
    tree.array[index] = {'tree_node_secret' => secret, 'ratchet_secret_generation' => 0}
    unless MLS::Tree.leaf?(index)
      left_secret  = MLS::Crypto.expand_with_label(suite, secret, "tree", "left", suite.kdf.n_h)
      right_secret = MLS::Crypto.expand_with_label(suite, secret, "tree", "right", suite.kdf.n_h)
      populate_tree_impl(suite, tree, MLS::Tree.left(index), left_secret)
      populate_tree_impl(suite, tree, MLS::Tree.right(index), right_secret)
    end
  end

  def self.ratchet(suite, tree, leaf_index)
    node_index = leaf_index * 2
    tree_node_secret = tree.array[node_index]['tree_node_secret']
    generation = tree.array[node_index]['ratchet_secret_generation']
    if generation == 0
      handshake_ratchet_secret   = MLS::Crypto.expand_with_label(suite, tree_node_secret, "handshake",   "", suite.kdf.n_h)
      application_ratchet_secret = MLS::Crypto.expand_with_label(suite, tree_node_secret, "application", "", suite.kdf.n_h)
    else
      handshake_ratchet_secret = tree.array[node_index]['handshake_ratchet_secret']
      application_ratchet_secret = tree.array[node_index]['application_ratchet_secret']
    end
    handshake_nonce = MLS::Crypto.derive_tree_secret(suite, handshake_ratchet_secret, "nonce", generation, suite.hpke.n_n)
    handshake_key   = MLS::Crypto.derive_tree_secret(suite, handshake_ratchet_secret, "key",   generation, suite.hpke.n_k)
    application_nonce = MLS::Crypto.derive_tree_secret(suite, application_ratchet_secret, "nonce", generation, suite.hpke.n_n)
    application_key   = MLS::Crypto.derive_tree_secret(suite, application_ratchet_secret, "key",   generation, suite.hpke.n_k)

    next_handshake_ratchet_secret   = MLS::Crypto.derive_tree_secret(suite, handshake_ratchet_secret, "secret", generation, suite.kdf.n_h)
    next_application_ratchet_secret = MLS::Crypto.derive_tree_secret(suite, application_ratchet_secret, "secret", generation, suite.kdf.n_h)
    tree.array[node_index] = {
      'ratchet_secret_generation' => generation + 1,
      'handshake_nonce' => handshake_nonce,
      'handshake_key' => handshake_key,
      'handshake_ratchet_secret' => next_handshake_ratchet_secret,
      'application_nonce' => application_nonce,
      'application_key' => application_key,
      'application_ratchet_secret' => next_application_ratchet_secret
    }
  end
end
