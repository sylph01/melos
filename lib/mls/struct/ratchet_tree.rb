## Ratchet Tree Extension (12.4.3.3)
require_relative 'base'
require_relative 'structs'
require_relative '../vec'
require_relative '../tree'
require_relative '../crypto'

module Melos::Struct::RatchetTree
  def self.parse(vec)
    array, _ = new_and_rest(vec)
    array
  end

  def self.new_and_rest(vec)
    array = []
    buf, rest = Melos::Vec.parse_vec(vec)
    while buf.bytesize > 0
      presence = buf.byteslice(0, 1).unpack1('C')
      buf = buf.byteslice(1..)
      case presence
      when 0
        array << nil
      when 1
        node, buf = Melos::Struct::Node.new_and_rest(buf)
        array << node
      end
    end
    [array, rest]
  end

  def self.raw(array)
    buf = ''
    array.each do |optional_node|
      if optional_node.nil?
        buf += [0].pack('C')
      else
        buf += [1].pack('C')
        buf += optional_node.raw
      end
    end

    Melos::Vec.from_string(buf)
  end

  def self.tree_hash(tree, node_index, suite)
    node = tree[node_index]
    if Melos::Tree.leaf?(node_index)
      # is a leaf node
      leaf_index = node_index / 2
      leaf_node_hash_input = [leaf_index].pack('L>')
      if node.nil?
        leaf_node_hash_input += [0].pack('C')
      else
        leaf_node_hash_input += [1].pack('C') + node.leaf_node.raw
      end

      tree_hash_input = [1].pack('C') + leaf_node_hash_input
    else
      # is a parent node, so calculate using ParentNodeHashInput
      parent_node_hash_input = ''
      if node.nil?
        parent_node_hash_input += [0].pack('C')
      else
        parent_node_hash_input += [1].pack('C') + node.parent_node.raw
      end
      parent_node_hash_input += Melos::Vec.from_string(tree_hash(tree, Melos::Tree.left(node_index), suite))
      parent_node_hash_input += Melos::Vec.from_string(tree_hash(tree, Melos::Tree.right(node_index), suite))

      tree_hash_input = [2].pack('C') + parent_node_hash_input
    end

    # The RFC omits the actual definition of calculating a tree hash...
    # it could totally be a ExpandWithLabel-ish thing...
    Melos::Crypto.hash(suite, tree_hash_input)
  end

  def self.tree_hash_except(tree, node_index, unmerged_leaves, suite)
    new_tree = tree.dup
    unmerged_leaves.each do |leaf_index|
      node_index_to_remove = leaf_index * 2
      new_tree[node_index_to_remove] = nil
    end

    tree_hash(new_tree, node_index, suite)
  end

  def self.calculate_parent_hash(tree, node_index, sibling, suite)
    parent_node = tree[node_index].parent_node
    sibling_hash = tree_hash_except(tree, sibling, parent_node.unmerged_leaves, suite)
    Melos::Crypto.parent_hash(suite, parent_node.encryption_key, parent_node.parent_hash, sibling_hash)
  end

  def self.verify_parent_hash_at(tree, node_index, suite)
    node = tree[node_index]
    if Melos::Tree.leaf?(node_index)
      false # maybe an ArgumentError, because there is no verifying a ParentHash on a leaf node
    else
      if node.nil?
        true
      else
        left_index  = Melos::Tree.left(node_index)
        right_index = Melos::Tree.right(node_index)

        # either the node at node_index is Parent-Hash Valid wrt someone in left tree or someone in right tree
        has_parent_hash(tree, left_index, calculate_parent_hash(tree, node_index, right_index, suite)) || has_parent_hash(tree, right_index, calculate_parent_hash(tree, node_index, left_index, suite))
      end
    end
  end

  def self.has_parent_hash(tree, child_index, parent_hash_value)
    resolutions = Melos::Tree.resolution(tree, child_index)
    resolutions.each do |node_index|
      if tree[node_index]&.parent_hash_in_node == parent_hash_value
        # if any of the resolution of specified child has matching parent_hash_value then parent is Parent-Hash Valid wrt that child
        return true
      end
    end
    return false
  end

  def self.verify_parent_hash_of_tree(tree, suite)
    parent_indexes = (1..((tree.count - 1) / 2)).map { _1 * 2 - 1} # this makes node_indexes of odd numbers
    parent_indexes_from_bottom_to_top = parent_indexes.sort_by { Melos::Tree.level(_1) } # this sorts node_indexes based on level
    parent_indexes_from_bottom_to_top.all? { verify_parent_hash_at(tree, _1, suite) } # this makes it so that nodes are evaluated from lower level to higher level
  end

  def self.add_leaf_node(tree, node_to_insert)
    inserted = false
    inserted_node_index = 0
    # if there is a blank in tree, insert there
    tree.each_with_index do |node, node_index|
      if Melos::Tree.leaf?(node_index)
        if tree[node_index].nil?
          tree[node_index] = node_to_insert
          inserted = true
          inserted_node_index = node_index
        end
      else
        # do nothing to a parent
      end
    end
    # if not, extend tree
    if !inserted
      tree << nil
      tree << node_to_insert
      inserted_node_index = tree.count - 1
    end
    # then update unmerged list up till root
    inserted_leaf_index = inserted_node_index / 2
    current_node_index = inserted_node_index
    while(current_node_index != Melos::Tree.root(tree.count))
      if tree[current_node_index] && tree[current_node_index].node_type == 0x02
        tree[current_node_index].parent_node.unmerged_leaves << inserted_leaf_index
      end
      current_node_index = Melos::Tree.parent(current_node_index, tree.count)
    end
  end

  def self.update_leaf_node(tree, node_to_update, leaf_index_of_sender)
    node_index = leaf_index_of_sender * 2
    tree[node_index] = node_to_update
    # blank the intermediate nodes along the path from sender's leaf to root
    current_node_index = node_index
    while(current_node_index != Melos::Tree.root(tree.count))
      if tree[current_node_index] && tree[current_node_index].node_type == 0x02
        tree[current_node_index] = nil
      end
      current_node_index = Melos::Tree.parent(current_node_index, tree.count)
    end
  end

  def self.remove_leaf_node(tree, leaf_index_to_remove)
    node_index = leaf_index_to_remove * 2
    tree[node_index] = nil
    # blank the intermediate nodes along the path from sender's leaf to root
    current_node_index = node_index
    while(current_node_index != Melos::Tree.root(tree.count))
      if tree[current_node_index] && tree[current_node_index].node_type == 0x02
        tree[current_node_index] = nil
      end
      current_node_index = Melos::Tree.parent(current_node_index, tree.count)
    end
    # then truncate tree
    Melos::Tree.truncate!(tree)
  end

  def self.root_tree_hash(suite, tree)
    root_index = Melos::Tree.root(Melos::Tree.n_leaves(tree))
    tree_hash(tree, root_index, suite)
  end

  def self.merge_update_path(suite, ratchet_tree, leaf_index, update_path)
    node_index_of_leaf = leaf_index * 2
    filtered_direct_path = Melos::Tree.filtered_direct_path(ratchet_tree, leaf_index)
    nodes_from_update_path = update_path.nodes

    parent_hashes = calculate_parent_hashes(suite, ratchet_tree, leaf_index, update_path.nodes)
    # update parent nodes on path
    filtered_direct_path.each_with_index do |node_index, path_index|
      parent_node = Melos::Struct::ParentNode.create(
        encryption_key: nodes_from_update_path[path_index].encryption_key,
        parent_hash: parent_hashes[path_index + 1],
        unmerged_leaves: []
      )
      node = Melos::Struct::Node.new_parent_node(parent_node)
      ratchet_tree[node_index] = node
    end
    # update leaf
    node = Melos::Struct::Node.new_leaf_node(update_path.leaf_node)
    ratchet_tree[node_index_of_leaf] = node
  end

  def self.calculate_parent_hashes(suite, ratchet_tree, leaf_index_from, update_path_nodes)
    hashes = []
    filtered_direct_path = Melos::Tree.filtered_direct_path(ratchet_tree, leaf_index_from)
    # count down from root, calculate parent hash
    calculated_parent_hash = ""
    # node_index = Melos::Tree.root(Melos::Tree.n_leaves(ratchet_tree))
    # puts "fdp count: #{filtered_direct_path.count}"
    # puts "update path count: #{nodes_from_update_path.count}"
    hashes[filtered_direct_path.count] = ''
    (filtered_direct_path.count - 1).downto(0) do |path_index|
      node_index = filtered_direct_path[path_index]
      leaf_node_index = leaf_index_from * 2
      sibling_node_index = Melos::Tree.sibling_from_leaf(leaf_node_index, node_index, Melos::Tree.n_leaves(ratchet_tree))
      encryption_key = update_path_nodes[path_index].encryption_key
      sibling_node = ratchet_tree[sibling_node_index]
      sibling_hash = Melos::Struct::RatchetTree.tree_hash(ratchet_tree, sibling_node_index, suite)
      calculated_parent_hash = Melos::Crypto.parent_hash(suite, encryption_key, calculated_parent_hash, sibling_hash)
      hashes[path_index] = calculated_parent_hash
    end

    hashes
  end

  def self.decrypt_path_secret(suite, ratchet_tree, encryption_priv_tree, update_path, sender_leaf_index, receiver_leaf_index, group_context)
    sender_node_index = sender_leaf_index * 2
    receiver_node_index = receiver_leaf_index * 2

    filtered_direct_path = Melos::Tree.filtered_direct_path(ratchet_tree, sender_leaf_index)
    # puts "filtered direct path: #{filtered_direct_path}"
    raise ArgumentError.new('malformed update path') unless filtered_direct_path.count == update_path.nodes.count
    overlap_node = Melos::Tree.overlap_with_filtered_direct_path(receiver_node_index, filtered_direct_path, Melos::Tree.n_leaves(ratchet_tree))
    # puts "overlap node: #{overlap_node}"
    overlap_index = filtered_direct_path.find_index { _1 == overlap_node}
    # puts "overlap index: #{overlap_index}"
    copath_node_index = Melos::Tree.copath_nodes_of_filtered_direct_path(ratchet_tree, sender_leaf_index)[overlap_index]
    # puts "copath node: #{copath_node_index}"
    resolution_of_copath_node = Melos::Tree.resolution(ratchet_tree, copath_node_index)
    # puts "resolution: #{resolution_of_copath_node}"

    priv_key = nil
    priv_index = nil
    resolution_of_copath_node.each_with_index do |res, idx|
      if encryption_priv_tree[res]
        priv_key = encryption_priv_tree[res]
        priv_index = idx
      end
    end

    target_update_path_node = update_path.nodes[overlap_index]
    raise ArgumentError.new('# of resolution of copath node does not match with # of encrypted path secrets') unless target_update_path_node.encrypted_path_secret.count == resolution_of_copath_node.count
    target_encrypted_path_secret = target_update_path_node.encrypted_path_secret[priv_index]
    raise ArgumentError.new('priv key not found in tree') if priv_key.nil?
    pkey = suite.pkey.deserialize_private_encapsulation_key(priv_key)

    Melos::Crypto.decrypt_with_label(suite, priv_key, "UpdatePathNode", group_context.raw, target_encrypted_path_secret.kem_output, target_encrypted_path_secret.ciphertext)
  end

  def self.calculate_commit_secret(suite, ratchet_tree, update_path, sender_leaf_index, receiver_leaf_index, path_secret)
    sender_node_index = sender_leaf_index * 2
    receiver_node_index = receiver_leaf_index * 2

    filtered_direct_path = Melos::Tree.filtered_direct_path(ratchet_tree, sender_leaf_index)
    raise ArgumentError.new('malformed update path') unless filtered_direct_path.count == update_path.nodes.count
    overlap_node = Melos::Tree.overlap_with_filtered_direct_path(receiver_node_index, filtered_direct_path, Melos::Tree.n_leaves(ratchet_tree))
    overlap_index = filtered_direct_path.find_index { _1 == overlap_node}

    path_secret_n = path_secret
    index = overlap_index
    while filtered_direct_path[index] != Melos::Tree.root(Melos::Tree.n_leaves(ratchet_tree))
      path_secret_n = Melos::Crypto.derive_secret(suite, path_secret_n, "path")
      index += 1
    end
    Melos::Crypto.derive_secret(suite, path_secret_n, "path") # commit secret is node's path_secret +1
  end
end
