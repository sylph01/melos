require_relative 'tree'
require_relative 'crypto'
require_relative 'constants'

# The secret tree (RFC 9420 Section 9): the per-epoch tree of secrets derived from the
# encryption_secret, with the same shape as the ratchet tree. Only the two hash ratchets
# at each leaf are kept; the node secrets above them are discarded once derived.
class Melos::SecretTree
  # 9.1: a hash ratchet over one leaf's secret. Each generation yields a key and nonce
  # and steps the secret forward; older secrets are forgotten.
  class Ratchet
    attr_reader :next_generation

    def initialize(suite, secret)
      @suite = suite
      @secret = secret
      @next_generation = 0
      @current = nil # [key, nonce, generation] of the last generation derived
    end

    # derive the key and nonce of the current generation and step the ratchet
    def ratchet
      generation = @next_generation
      nonce = Melos::Crypto.derive_tree_secret(@suite, @secret, "nonce", generation, @suite.hpke.n_n)
      key   = Melos::Crypto.derive_tree_secret(@suite, @secret, "key",   generation, @suite.hpke.n_k)
      @secret = Melos::Crypto.derive_tree_secret(@suite, @secret, "secret", generation, @suite.kdf.n_h)
      @next_generation += 1
      @current = [key, nonce, generation]
    end

    # the key and nonce of the given generation, ratcheting forward as needed.
    # TODO (9.1): keep a window of unconsumed generations so that out-of-order messages can be decrypted
    def ratchet_until(generation)
      if generation < @next_generation - 1
        raise ArgumentError.new("generation #{generation} has already been consumed (next generation is #{@next_generation})")
      end
      ratchet while @next_generation <= generation
      @current
    end
  end

  attr_reader :suite, :n_leaves

  def initialize(suite, n_leaves, encryption_secret)
    @suite = suite
    @n_leaves = n_leaves
    @handshake_ratchets = []   # by leaf index
    @application_ratchets = [] # by leaf index
    populate(Melos::Tree.root(n_leaves), encryption_secret)
  end

  # sender side: the key and nonce of the next generation for this leaf and content type
  # returns [key, nonce, generation]
  def ratchet_and_get(content_type, leaf_index)
    ratchet_for(content_type, leaf_index).ratchet
  end

  # receiver side: the key and nonce of a given generation for this leaf and content type
  # returns [key, nonce, generation]
  def ratchet_until_and_get(content_type, leaf_index, generation)
    ratchet_for(content_type, leaf_index).ratchet_until(generation)
  end

  private

  # 9: derive the secrets of the subtree under node_index down to the leaves
  def populate(node_index, secret)
    if Melos::Tree.leaf?(node_index)
      leaf_index = node_index / 2
      @handshake_ratchets[leaf_index]   = Ratchet.new(@suite, Melos::Crypto.expand_with_label(@suite, secret, "handshake",   "", @suite.kdf.n_h))
      @application_ratchets[leaf_index] = Ratchet.new(@suite, Melos::Crypto.expand_with_label(@suite, secret, "application", "", @suite.kdf.n_h))
    else
      left_secret  = Melos::Crypto.expand_with_label(@suite, secret, "tree", "left",  @suite.kdf.n_h)
      right_secret = Melos::Crypto.expand_with_label(@suite, secret, "tree", "right", @suite.kdf.n_h)
      populate(Melos::Tree.left(node_index),  left_secret)
      populate(Melos::Tree.right(node_index), right_secret)
    end
  end

  # 9.1: handshake messages (proposals and commits) and application messages use separate ratchets
  def ratchet_for(content_type, leaf_index)
    ratchets = case content_type
               when Melos::Constants::ContentType::PROPOSAL, Melos::Constants::ContentType::COMMIT
                 @handshake_ratchets
               when Melos::Constants::ContentType::APPLICATION
                 @application_ratchets
               else
                 raise ArgumentError.new("unknown content type #{content_type}")
               end
    ratchets[leaf_index] or raise ArgumentError.new("no leaf #{leaf_index} in secret tree with #{@n_leaves} leaves")
  end
end
