require 'securerandom'
require_relative 'tree'
require_relative 'crypto'
require_relative 'vec'
require_relative 'constants'
require_relative 'struct/structs'

# The ratchet tree (RFC 9420 Section 7) in the array representation of Appendix C:
# nodes[i] is the Melos::Struct::Node at node index i, or nil for a blank node.
#
# The tree is always full (7.7): the number of leaves is a power of two, so @nodes
# always has 2^(d+1) - 1 entries. Extending the tree doubles it with a blank right
# subtree, and truncating halves it while the right subtree is entirely blank.
#
# This is the public tree every member of a group shares. A member's own private keys
# are kept separately in a Melos::PrivateTree and handed to the methods that need them.
#
# Wire format is the ratchet_tree extension (12.4.3.3): optional<Node> ratchet_tree<V>,
# with the blank nodes after the last non-blank node left out.
class Melos::RatchetTree
  attr_reader :suite, :nodes

  # nodes may omit trailing blanks (as the wire format does); it is padded to a full tree
  def initialize(suite, nodes = [])
    @suite = suite
    @nodes = nodes
    pad_to_full_tree!
  end

  # 12.4.3.3: the sender leaves out the blank nodes after the last non-blank node,
  # so the last node must be non-blank; the receiver extends the tree back to 2^(d+1) - 1 nodes
  def self.parse(suite, stream)
    stream = StringIO.new(stream) if stream.is_a?(String)
    nodes = []
    data_stream = StringIO.new(Melos::Vec.parse_stream(stream))
    until data_stream.eof?
      presence = data_stream.read(1).unpack1('C')
      nodes << (presence == 1 ? Melos::Struct::Node.new(data_stream) : nil)
    end
    raise ArgumentError.new('last node of ratchet_tree must not be blank') if !nodes.empty? && nodes.last.nil?
    new(suite, nodes)
  end

  # 12.4.3.3: blank nodes after the last non-blank node are not included
  def raw
    last = @nodes.rindex { !_1.nil? }
    encoded = last.nil? ? [] : @nodes[0..last]
    buf = encoded.map { |node| node.nil? ? [0].pack('C') : [1].pack('C') + node.raw }.join
    Melos::Vec.string_to_vec(buf)
  end

  # deep copy via the wire format, so that in-place changes to nodes
  # (e.g. unmerged_leaves) on one copy do not affect the other
  def dup
    self.class.parse(@suite, raw)
  end

  def [](node_index)
    @nodes[node_index]
  end

  def node_count
    @nodes.count
  end

  # a power of two; some of the leaves may be blank
  def n_leaves
    (@nodes.count + 1) / 2
  end

  # node index of the root
  def root
    Melos::Tree.root(n_leaves)
  end

  # the Melos::Struct::LeafNode at leaf_index, or nil if that leaf is blank
  def leaf_node_at(leaf_index)
    @nodes[leaf_index * 2]&.leaf_node
  end

  # yields each non-blank leaf node with its leaf index
  def each_leaf_node
    (0...n_leaves).each do |leaf_index|
      leaf_node = leaf_node_at(leaf_index)
      yield leaf_node, leaf_index unless leaf_node.nil?
    end
  end

  # leaf index of the first non-blank leaf for which the block is true, or nil
  def find_leaf_index
    each_leaf_node { |leaf_node, leaf_index| return leaf_index if yield(leaf_node) }
    nil
  end

  ## Tree math that depends on the tree's contents (7.2, 7.8); pure index math lives in Melos::Tree

  # 7.2: node indexes a message to this node must be encrypted to
  def resolution(node_index)
    node = @nodes[node_index]
    if node.nil?
      if Melos::Tree.leaf?(node_index)
        # The resolution of a blank leaf node is the empty list.
        []
      else
        # The resolution of a blank intermediate node is the result of concatenating the resolution of
        # its left child with the resolution of its right child, in that order.
        resolution(Melos::Tree.left(node_index)) + resolution(Melos::Tree.right(node_index))
      end
    elsif node.parent_node
      # The resolution of a non-blank node comprises the node itself, followed by its list of unmerged leaves, if any.
      [node_index] + node.parent_node.unmerged_leaves.map { _1 * 2 } # leaf index -> node index
    else
      [node_index]
    end
  end

  # 7.8: direct path of node_index minus the nodes whose copath child has an empty resolution
  def filtered_direct_path(node_index)
    Melos::Tree.direct_path(node_index, n_leaves).reject do |ancestor|
      resolution(Melos::Tree.sibling_from_leaf(node_index, ancestor, n_leaves)) == []
    end
  end

  # for each node on the filtered direct path of node_index, its child on the copath side
  def copath_nodes_of_filtered_direct_path(node_index)
    filtered_direct_path(node_index).map { Melos::Tree.sibling_from_leaf(node_index, _1, n_leaves) }
  end

  # 7.7: while the right subtree of the root is entirely blank, drop it, halving the tree
  def truncate!
    return if n_leaves <= 1
    r = root
    if @nodes[(r + 1)..].all?(nil)
      @nodes.slice!(r..) # the left child of the root becomes the root
      truncate!
    end
  end

  ## Tree hashes (7.8) and parent hashes (7.9)

  def tree_hash(node_index = root)
    node = @nodes[node_index]
    if Melos::Tree.leaf?(node_index)
      leaf_node_hash_input = [node_index / 2].pack('L>') # leaf index
      leaf_node_hash_input += node.nil? ? [0].pack('C') : [1].pack('C') + node.leaf_node.raw
      tree_hash_input = [1].pack('C') + leaf_node_hash_input # node_type = leaf
    else
      parent_node_hash_input = node.nil? ? [0].pack('C') : [1].pack('C') + node.parent_node.raw
      parent_node_hash_input += Melos::Vec.string_to_vec(tree_hash(Melos::Tree.left(node_index)))
      parent_node_hash_input += Melos::Vec.string_to_vec(tree_hash(Melos::Tree.right(node_index)))
      tree_hash_input = [2].pack('C') + parent_node_hash_input # node_type = parent
    end
    Melos::Crypto.hash(@suite, tree_hash_input)
  end

  def root_tree_hash
    tree_hash(root)
  end

  # 7.9.2: tree hash of node_index computed as if the given leaves were blank
  def tree_hash_except(node_index, unmerged_leaves)
    blanked = @nodes.dup
    unmerged_leaves.each { blanked[_1 * 2] = nil }
    self.class.new(@suite, blanked).tree_hash(node_index)
  end

  # 7.9: the parent hash of the parent node at node_index, for the child opposite to sibling_index
  def parent_hash_of(node_index, sibling_index)
    parent_node = @nodes[node_index].parent_node
    sibling_hash = tree_hash_except(sibling_index, parent_node.unmerged_leaves)
    Melos::Crypto.parent_hash(@suite, parent_node.encryption_key, parent_node.parent_hash, sibling_hash)
  end

  # 7.9.2: the parent node at node_index is parent-hash valid with respect to one of its children
  def parent_hash_valid_at?(node_index)
    return false if Melos::Tree.leaf?(node_index) # there is no parent hash to verify on a leaf
    return true if @nodes[node_index].nil?
    left  = Melos::Tree.left(node_index)
    right = Melos::Tree.right(node_index)
    has_parent_hash?(left, parent_hash_of(node_index, right)) || has_parent_hash?(right, parent_hash_of(node_index, left))
  end

  # 7.9.2: every parent node in the tree is parent-hash valid; checked from the bottom level up
  def parent_hash_valid?
    parent_indexes = (1..((@nodes.count - 1) / 2)).map { _1 * 2 - 1 } # odd node indexes
    parent_indexes.sort_by { Melos::Tree.level(_1) }.all? { parent_hash_valid_at?(_1) }
  end

  # 7.9.1: parent hashes along the filtered direct path of leaf_index, given the new encryption keys of an UpdatePath.
  # hashes[i] is the parent hash of the i-th filtered direct path node, which is stored in the node below it:
  # hashes[0] goes into the leaf, hashes[i] into filtered direct path node i-1, and hashes[count] is '' (the root).
  def calculate_parent_hashes(leaf_index, update_path_nodes)
    fdp = filtered_direct_path(leaf_index * 2)
    hashes = []
    hashes[fdp.count] = ''
    calculated = ''
    (fdp.count - 1).downto(0) do |i|
      sibling_index = Melos::Tree.sibling_from_leaf(leaf_index * 2, fdp[i], n_leaves)
      calculated = Melos::Crypto.parent_hash(@suite, update_path_nodes[i].encryption_key, calculated, tree_hash(sibling_index))
      hashes[i] = calculated
    end
    hashes
  end

  # 7.9.2: the leaf node of update_path carries the parent hash its path implies on this tree
  def verify_parent_hash_of_path(leaf_index, update_path)
    update_path.leaf_node.parent_hash == calculate_parent_hashes(leaf_index, update_path.nodes)[0]
  end

  ## Applying proposals (12.1)

  # 12.1.1 Add: place the leaf at the leftmost blank leaf, extending the tree if there is none (7.7:
  # a new blank root whose left subtree is the existing tree and right subtree is all blank);
  # record it as unmerged on every non-blank parent above it. Returns the new leaf index.
  def add_leaf_node(leaf_node)
    node = Melos::Struct::Node.new_leaf_node(leaf_node)
    if @nodes.empty?
      @nodes << node
      return 0
    end
    inserted_node_index = (0...@nodes.count).step(2).find { @nodes[_1].nil? }
    if inserted_node_index.nil?
      @nodes.concat(Array.new(@nodes.count + 1)) # doubles the tree; the old root's index is the new blank root
      inserted_node_index = (0...@nodes.count).step(2).find { @nodes[_1].nil? }
    end
    @nodes[inserted_node_index] = node
    inserted_leaf_index = inserted_node_index / 2
    Melos::Tree.direct_path(inserted_node_index, n_leaves).each do |ancestor|
      @nodes[ancestor].parent_node.unmerged_leaves << inserted_leaf_index if @nodes[ancestor]&.parent_node
    end
    inserted_leaf_index
  end

  # 12.1.2 Update: replace the leaf and blank its direct path
  def update_leaf_node(leaf_index, leaf_node)
    @nodes[leaf_index * 2] = Melos::Struct::Node.new_leaf_node(leaf_node)
    blank_direct_path(leaf_index * 2)
  end

  # 12.1.3 Remove: blank the leaf and its direct path, then truncate the tree
  def remove_leaf_node(leaf_index)
    @nodes[leaf_index * 2] = nil
    blank_direct_path(leaf_index * 2)
    truncate!
  end

  ## TreeKEM (7.4, 7.5, 12.4.2)

  # 7.5 (both sides): replace the sender's leaf and the parent nodes on its filtered direct path with those in update_path
  def merge_update_path(leaf_index, update_path)
    node_index = leaf_index * 2
    fdp = filtered_direct_path(node_index)
    raise ArgumentError.new('malformed update path') unless fdp.count == update_path.nodes.count
    parent_hashes = calculate_parent_hashes(leaf_index, update_path.nodes)
    fdp.each_with_index do |fdp_node_index, i|
      parent_node = Melos::Struct::ParentNode.create(
        encryption_key: update_path.nodes[i].encryption_key,
        parent_hash: parent_hashes[i + 1],
        unmerged_leaves: []
      )
      @nodes[fdp_node_index] = Melos::Struct::Node.new_parent_node(parent_node)
    end
    @nodes[node_index] = Melos::Struct::Node.new_leaf_node(update_path.leaf_node)
  end

  # 7.5 (sender side): build an UpdatePath from a fresh leaf secret. Does not modify this tree; the caller
  # merges the returned path with #merge_update_path once the commit is in place. The sender's new leaf
  # private key and the private keys of its filtered direct path are written into private_tree.
  #   except: node indexes to leave out of the copath resolutions (leaves being added by the same commit)
  # Returns { update_path:, commit_secret: }.
  def create_update_path(private_tree, sender_leaf_index, signature_private_key, group_id, group_context, except = [])
    tree = dup
    sender_node_index = sender_leaf_index * 2
    original_leaf_node = tree.leaf_node_at(sender_leaf_index)
    fdp = tree.filtered_direct_path(sender_node_index)

    # 7.4: path secrets up the filtered direct path; the commit secret is one more derivation past the last one
    leaf_secret = SecureRandom.random_bytes(@suite.kdf.n_h)
    path_secrets = []
    secret = leaf_secret
    fdp.each do
      secret = Melos::Crypto.derive_secret(@suite, secret, "path")
      path_secrets << secret
    end
    commit_secret = Melos::Crypto.derive_secret(@suite, secret, "path")

    leaf_private_key, leaf_public_key = Melos::Crypto.derive_key_pair(@suite, Melos::Crypto.derive_secret(@suite, leaf_secret, "node"))
    node_key_pairs = path_secrets.map { Melos::Crypto.derive_key_pair(@suite, Melos::Crypto.derive_secret(@suite, _1, "node")) }

    # parent hashes depend on the new public keys only, so compute them from nodes without ciphertexts
    bare_nodes = node_key_pairs.map { |_priv, pub| Melos::Struct::UpdatePathNode.create(encryption_key: pub, encrypted_path_secret: []) }
    parent_hashes = tree.calculate_parent_hashes(sender_leaf_index, bare_nodes)
    new_leaf_node = Melos::Struct::LeafNode.create(
      encryption_key: leaf_public_key,
      signature_key: original_leaf_node.signature_key,
      credential: original_leaf_node.credential,
      capabilities: original_leaf_node.capabilities,
      leaf_node_source: Melos::Constants::LeafNodeSource::COMMIT,
      lifetime: original_leaf_node.lifetime,
      parent_hash: parent_hashes[0],
      extensions: original_leaf_node.extensions,
      signature: nil
    )
    new_leaf_node.sign(@suite, signature_private_key, group_id, sender_leaf_index)

    # merge into the copy so the copath resolutions below are those of the tree the receivers will see
    tree.merge_update_path(sender_leaf_index, Melos::Struct::UpdatePath.create(leaf_node: new_leaf_node, nodes: bare_nodes))

    copath_nodes = tree.copath_nodes_of_filtered_direct_path(sender_node_index)
    nodes = fdp.each_index.map do |i|
      ciphertexts = (tree.resolution(copath_nodes[i]) - except).map do |resolution_node_index|
        kem_output, ciphertext = Melos::Crypto.encrypt_with_label(
          @suite, tree[resolution_node_index].public_encryption_key, "UpdatePathNode", group_context.raw, path_secrets[i]
        )
        Melos::Struct::HPKECipherText.create(kem_output: kem_output, ciphertext: ciphertext)
      end
      Melos::Struct::UpdatePathNode.create(encryption_key: node_key_pairs[i][1], encrypted_path_secret: ciphertexts)
    end

    private_tree[sender_node_index] = leaf_private_key
    fdp.each_with_index { |fdp_node_index, i| private_tree[fdp_node_index] = node_key_pairs[i][0] }

    {
      update_path: Melos::Struct::UpdatePath.create(leaf_node: new_leaf_node, nodes: nodes),
      commit_secret: commit_secret
    }
  end

  # 7.5 (receiver side), on the tree with update_path already merged: decrypt the path secret of the node where
  # the receiver's direct path meets the sender's filtered direct path, and derive the private keys from that
  # node up to the root into private_tree.
  #   leaves_to_remove: leaf indexes (added by the same commit) left out of the copath resolution
  # Returns the decrypted path secret, for #calculate_commit_secret.
  def decrypt_path_secret(private_tree, update_path, sender_leaf_index, receiver_leaf_index, group_context, leaves_to_remove = [])
    fdp = filtered_direct_path(sender_leaf_index * 2)
    raise ArgumentError.new('malformed update path') unless fdp.count == update_path.nodes.count
    overlap_node_index = Melos::Tree.overlap_with_filtered_direct_path(receiver_leaf_index * 2, fdp, n_leaves)
    overlap_index = fdp.index(overlap_node_index)
    copath_node_index = copath_nodes_of_filtered_direct_path(sender_leaf_index * 2)[overlap_index]
    resolution = resolution(copath_node_index) - leaves_to_remove.map { _1 * 2 } # leaf index -> node index
    update_path_node = update_path.nodes[overlap_index]
    raise ArgumentError.new('# of resolution of copath node does not match with # of encrypted path secrets') unless update_path_node.encrypted_path_secret.count == resolution.count

    priv_index = resolution.rindex { private_tree[_1] }
    raise ArgumentError.new("priv key not found in tree (sender leaf index: #{sender_leaf_index})") if priv_index.nil?
    encrypted_path_secret = update_path_node.encrypted_path_secret[priv_index]
    path_secret = Melos::Crypto.decrypt_with_label(
      @suite, private_tree[resolution[priv_index]], "UpdatePathNode", group_context.raw,
      encrypted_path_secret.kem_output, encrypted_path_secret.ciphertext
    )

    private_tree.set_path_secret(self, overlap_node_index, path_secret)
    path_secret
  end

  # 7.4: the commit secret is the path secret one derivation past the last node of the sender's filtered direct path
  def calculate_commit_secret(update_path, sender_leaf_index, receiver_leaf_index, path_secret)
    fdp = filtered_direct_path(sender_leaf_index * 2)
    raise ArgumentError.new('malformed update path') unless fdp.count == update_path.nodes.count
    overlap_node_index = Melos::Tree.overlap_with_filtered_direct_path(receiver_leaf_index * 2, fdp, n_leaves)
    secret = path_secret
    (fdp.count - 1 - fdp.index(overlap_node_index)).times do
      secret = Melos::Crypto.derive_secret(@suite, secret, "path")
    end
    Melos::Crypto.derive_secret(@suite, secret, "path")
  end

  # for debugging
  def dump
    @nodes.each_with_index do |node, index|
      if node.nil?
        puts "#{index}, nil"
      elsif node.parent_node
        puts "#{index}, PN (#{Melos::Util.to_hex(node.public_encryption_key)[0, 8]}) - #{node.parent_node.unmerged_leaves}"
      else
        puts "#{index}, LN (#{Melos::Util.to_hex(node.public_encryption_key)[0, 8]})"
      end
    end
  end

  private

  # extend @nodes with blanks to the next full tree size 2^(d+1) - 1
  def pad_to_full_tree!
    return if @nodes.empty?
    full_leaves = 1
    full_leaves <<= 1 while full_leaves < n_leaves
    @nodes.concat(Array.new(Melos::Tree.node_width(full_leaves) - @nodes.count))
  end

  def has_parent_hash?(child_index, parent_hash_value)
    resolution(child_index).any? { @nodes[_1]&.parent_hash_in_node == parent_hash_value }
  end

  def blank_direct_path(node_index)
    Melos::Tree.direct_path(node_index, n_leaves).each { @nodes[_1] = nil }
  end
end
