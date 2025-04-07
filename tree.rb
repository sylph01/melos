module MLS; end

class MLS::Tree
  attr_accessor :array, :leaf_count
  # attr_reader @array

  def initialize
    @array = []
    @leaf_count = 0
  end

  def self.empty_tree(n_leaves)
    instance = self.allocate
    instance.leaf_count = n_leaves
    instance.array = Array.new(node_width(n_leaves))
    instance
  end

  def add(val)
    raise ArgumentError.new('Cannot add nil element') if val.nil?
    if @leaf_count == 0
      # initialize tree with one node
      @array = [val]
      @leaf_count = 1
    else
      # find leftmost empty leaf
      extend_tree = true
      for k in 0 .. (@leaf_count - 1) do
        if @array[k * 2].nil?
          @array[k * 2] = val
          extend_tree = false
          break
        end
      end
      if extend_tree
        # if tree is full, extend
        @leaf_count = @leaf_count * 2
        for k in 0 .. @leaf_count - 2
          @array[@leaf_count + k] = nil
        end
        @array[@leaf_count] = val
      end
    end
    @array
  end

  def remove_leaf(leaf_idx)
    raise ArgumentError.new('Cannot remove from empty tree') if @leaf_count == 0
    remove_node(leaf_idx * 2)
    # then if rigbt half of the tree is empty, truncate tree
    # q: do we recursively shrink tree?
    right_tree_empty = true
    for i in 0 .. (@leaf_count / 2) - 1 do
      if !@array[@leaf_count + 2 * i].nil?
        right_tree_empty = false
        break
      end
    end
    if right_tree_empty
      @array = @array.first(@leaf_count - 1)
      @leaf_count = @leaf_count / 2
    end
    @array
  end

  def remove_node(node_idx)
    @array[node_idx] = nil
  end

  def root
    self.class.root(@leaf_count)
  end

  def leaf_at(leaf_index)
    @array[leaf_index * 2]
  end

  class << self
    def n_leaves(tree)
      (tree.size + 1) / 2
    end

    def log2(x)
      if x == 0
        return 0
      end
      k = 0
      while (x >> k) > 0
        k += 1
      end
      return (k - 1)
    end

    def level(x)
      if x & 0x01 == 0
        return 0
      end
      k = 0
      while ((x >> k) & 0x01) == 1
        k += 1
      end
      return k
    end

    def node_width(n)
      if n == 0
        0
      else
        2 * (n - 1) + 1
      end
    end

    def root(n_leaves)
      w = node_width(n_leaves)

      (1 << log2(w)) - 1
    end

    def left(x)
      k = level(x)
      raise ArgumentError.new('leaf node has no children') if k == 0
      x ^ (0x01 << (k - 1))
    end

    def right(x)
      k = level(x)
      raise ArgumentError.new('leaf node has no children') if k == 0
      x ^ (0x03 << (k - 1))
    end

    def parent(x, n)
      raise ArgumentError.new('root node has no parent') if x == root(n)
      k = level(x)
      b = (x >> (k +1)) & 0x01
      (x | (1 << k)) ^ (b << (k + 1))
    end

    def sibling(x, n)
      p = parent(x, n)
      if x < p
        right(p)
      else
        left(p)
      end
    end

    def direct_path(x, n)
      r = root(n)
      return [] if x == r
      d = []
      while x != r
        x = parent(x, n)
        d << x
      end
      return d
    end

    def copath(x, n)
      return [] if x == root(n)
      d = direct_path(x)
      d.insert(0, x)
      d.pop

      d.map { sibling(_1, n) }
    end

    def common_ancestor_semantic(x, y, n)
      dx = Set.new([x]) | Set.new(direct_path(x, n))
      dy = Set.new([y]) | Set.new(direct_path(y, n))
      dxy = dx & dy
      if dxy.size == 0
        raise ArgumentError.new('Failed to find common ancestor')
      end

      dxy.min { level(_1) }
    end

    def leaf?(node_index)
      node_index % 2 == 0
    end

    def truncate!(tree)
      last_node_index = tree.count - 1
      root = root(n_leaves(tree))
      if tree[(root + 1)..]&.all?(nil)
        tree.slice!(root..) # keep left half of tree
        truncate!(tree) # then attempt to truncate again
      end
      # right half of tree has an element, so finish
    end

    # def common_ancestor_direct(x, y)
    #   lx = level(x) + 1
    #   ly = level(y) + 1
    #   if (lx <= ly) && (x >> ly == y >> ly)
    #     return y
    #   elsif (ly <= lx) && (x >> lx == y >> lx)
    #     return x
    #   end

    #   xn = x
    #   yn = y
    #   k = 0
    #   while xn != yn
    #     xn = xn >> 1
    #     yn = yn >> 1
    #     k + 1
    #   end
    #   (xn << k) + (1 << (k - 1)) - 1
    # end
  end
end
