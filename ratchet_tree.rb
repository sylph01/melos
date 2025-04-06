## Ratchet Tree Extension (12.4.3.3)
require_relative 'mls_struct_base'
require_relative 'structs'
require_relative 'vec_base'
require_relative 'tree'

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
end
