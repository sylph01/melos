require_relative 'crypto'

# A member's private half of the ratchet tree (RFC 9420 Sections 7.4 and 7.5): the HPKE private
# keys this member holds, by node index. That is its own leaf, plus the parent nodes on its direct
# path whose path secrets it has learned, either by creating an UpdatePath or by decrypting one.
class Melos::PrivateTree
  def initialize(keys = {})
    @keys = keys
  end

  def [](node_index)
    @keys[node_index]
  end

  def []=(node_index, private_key)
    @keys[node_index] = private_key
  end

  def delete(node_index)
    @keys.delete(node_index)
  end

  def node_indexes
    @keys.keys.sort
  end

  def dup
    self.class.new(@keys.dup)
  end

  # 7.4: starting with path_secret at start_node_index, derive the node private key there and at
  # every node up its filtered direct path on ratchet_tree, each from the next path secret
  def set_path_secret(ratchet_tree, start_node_index, path_secret)
    suite = ratchet_tree.suite
    secret = path_secret
    ([start_node_index] + ratchet_tree.filtered_direct_path(start_node_index)).each do |node_index|
      node_secret = Melos::Crypto.derive_secret(suite, secret, "node")
      private_key, _public_key = Melos::Crypto.derive_key_pair(suite, node_secret)
      @keys[node_index] = private_key
      secret = Melos::Crypto.derive_secret(suite, secret, "path")
    end
  end

  # every private key here belongs to a non-blank node of ratchet_tree whose public key it matches
  def consistent?(ratchet_tree)
    @keys.all? do |node_index, private_key|
      node = ratchet_tree[node_index]
      !node.nil? && Melos::Crypto.encapsulation_key_pair_corresponds?(ratchet_tree.suite, private_key, node.public_encryption_key)
    end
  end
end
