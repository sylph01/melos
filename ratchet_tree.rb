## Ratchet Tree Extension (12.4.3.3)
require_relative 'mls_struct_base'
require_relative 'structs'
require_relative 'vec_base'
require_relative 'tree'
require_relative 'crypto'

module MLS; end
module MLS::Struct; end

module MLS::Struct::RatchetTree
  def self.parse(vec)
    array, _ = new_and_rest(vec)
    array
  end

  def self.new_and_rest(vec)
    array = []
    buf, rest = String.parse_vec(vec)
    while buf.bytesize > 0
      presence = buf.byteslice(0, 1).unpack1('C')
      buf = buf.byteslice(1..)
      case presence
      when 0
        array << nil
      when 1
        node, buf = MLSStruct::Node.new_and_rest(buf)
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

    buf.to_vec
  end

  def self.resolution(tree, node_index)
    node = tree[node_index]
    if node.nil?
      if MLS::Tree.leaf?(node_index)
        # The resolution of a blank leaf node is the empty list.
        []
      else
        # The resolution of a blank intermediate node is the result of concatenating the resolution of its left child with the resolution of its right child, in that order.
        resolution(tree, MLS::Tree.left(node_index)) + resolution(tree, MLS::Tree.right(node_index))
      end
    else
      # The resolution of a non-blank node comprises the node itself, followed by its list of unmerged leaves, if any.
      if node.parent_node
        [node_index] + node.parent_node.unmerged_leaves.map { _1 * 2} # convert leaf index to node index
      else
        [node_index]
      end
    end
  end

  def self.tree_hash(tree, node_index, suite)
    node = tree[node_index]
    if MLS::Tree.leaf?(node_index)
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
      parent_node_hash_input += tree_hash(tree, MLS::Tree.left(node_index), suite).to_vec
      parent_node_hash_input += tree_hash(tree, MLS::Tree.right(node_index), suite).to_vec

      tree_hash_input = [2].pack('C') + parent_node_hash_input
    end

    # The RFC omits the actual definition of calculating a tree hash...
    # it could totally be a ExpandWithLabel-ish thing...
    MLS::Crypto.hash(suite, tree_hash_input)
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
    parent_hash_input = parent_node.encryption_key.to_vec + parent_node.parent_hash.to_vec + sibling_hash.to_vec
    MLS::Crypto.hash(suite, parent_hash_input)
  end

  def self.verify_parent_hash_at(tree, node_index, suite)
    node = tree[node_index]
    if MLS::Tree.leaf?(node_index)
      false # maybe an ArgumentError, because there is no verifying a ParentHash on a leaf node
    else
      if node.nil?
        true
      else
        left_index  = MLS::Tree.left(node_index)
        right_index = MLS::Tree.right(node_index)

        # either the node at node_index is Parent-Hash Valid wrt someone in left tree or someone in right tree
        has_parent_hash(tree, left_index, calculate_parent_hash(tree, node_index, right_index, suite)) || has_parent_hash(tree, right_index, calculate_parent_hash(tree, node_index, left_index, suite))
      end
    end
  end

  def self.has_parent_hash(tree, child_index, parent_hash_value)
    resolutions = resolution(tree, child_index)
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
    parent_indexes_from_bottom_to_top = parent_indexes.sort_by { MLS::Tree.level(_1) } # this sorts node_indexes based on level
    parent_indexes_from_bottom_to_top.all? { verify_parent_hash_at(tree, _1, suite) } # this makes it so that nodes are evaluated from lower level to higher level
  end

  def self.add_leaf_node(tree, node_to_insert)
    inserted = false
    inserted_node_index = 0
    # if there is a blank in tree, insert there
    tree.each_with_index do |node, node_index|
      if MLS::Tree.leaf?(node_index)
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
    while(current_node_index != MLS::Tree.root(tree.count))
      if tree[current_node_index] && tree[current_node_index].node_type == 0x02
        tree[current_node_index].parent_node.unmerged_leaves << inserted_leaf_index
      end
      current_node_index = MLS::Tree.parent(current_node_index, tree.count)
    end
  end

  def self.update_leaf_node(tree, node_to_update, leaf_index_of_sender)
    node_index = leaf_index_of_sender * 2
    tree[node_index] = node_to_update
    # blank the intermediate nodes along the path from sender's leaf to root
    current_node_index = node_index
    while(current_node_index != MLS::Tree.root(tree.count))
      if tree[current_node_index] && tree[current_node_index].node_type == 0x02
        tree[current_node_index] = nil
      end
      current_node_index = MLS::Tree.parent(current_node_index, tree.count)
    end
  end
end
