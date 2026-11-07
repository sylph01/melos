# Tree math over node indexes in the array representation of a left-balanced binary tree (RFC 9420 Appendix C).
# Functions that depend on the tree's contents live on Melos::RatchetTree.
class Melos::Tree
  class << self
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

    def parent(x, n_leaves)
      raise ArgumentError.new('root node has no parent') if x == root(n_leaves)
      k = level(x)
      b = (x >> (k + 1)) & 0x01
      (x | (1 << k)) ^ (b << (k + 1))
    end

    def sibling(x, n_leaves)
      p = parent(x, n_leaves)
      if x < p
        right(p)
      else
        left(p)
      end
    end

    # used for determining sibling of a node from an UpdatePath
    # i.e. the node (sibling) on the copath side
    # takes two node indexes and the # of leaves
    def sibling_from_leaf(x_of_leaf, x_of_ancestor, n_leaves)
      dp = direct_path(x_of_leaf, n_leaves)
      dp_including_self = [x_of_leaf] + dp
      raise ArgumentError.new('specified node is not an ancestor of leaf') unless dp.include?(x_of_ancestor)
      l = left(x_of_ancestor)
      r = right(x_of_ancestor)
      # if direct path (including self) includes left side, return right, else return left
      dp_including_self.include?(l) ? r : l
    end

    def direct_path(x, n_leaves)
      r = root(n_leaves)
      return [] if x == r
      d = []
      while x != r
        x = parent(x, n_leaves)
        d << x
      end
      return d
    end

    def copath(x, n_leaves)
      return [] if x == root(n_leaves)

      d = direct_path(x, n_leaves)
      d.insert(0, x)
      d.pop

      d.map { sibling(_1, n_leaves) }
    end

    def common_ancestor_semantic(x, y, n)
      dx = Set.new([x]) | Set.new(direct_path(x, n))
      dy = Set.new([y]) | Set.new(direct_path(y, n))
      dxy = dx & dy
      if dxy.size == 0
        raise ArgumentError.new('Failed to find common ancestor')
      end

      dxy.min_by { level(_1) }
    end

    def overlap_with_filtered_direct_path(x, filtered_direct_path, n)
      dx = Set.new([x]) | Set.new(direct_path(x, n))
      df = Set.new(filtered_direct_path)
      dxf = dx & df
      if dxf.size == 0
        raise ArgumentError.new('Failed to find overlap')
      end

      dxf.min_by { level(_1) }
    end

    def leaf?(node_index)
      node_index % 2 == 0
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
