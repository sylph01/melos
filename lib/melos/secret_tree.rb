require_relative 'tree'
require_relative 'crypto'
require_relative 'constants'

# The secret tree (RFC 9420 Section 9): the per-epoch tree of secrets derived from the
# encryption_secret, with the same shape as the ratchet tree. Only the two hash ratchets
# at each leaf are kept; the node secrets above them are discarded once derived.
class Melos::SecretTree
  # 15.3: how far one message may move a receiving ratchet forward, and how many keys of skipped
  # generations a ratchet keeps for messages that arrive out of order. Both bound the work and memory
  # a single message can cost; the RFC leaves the values to the application.
  DEFAULT_MAX_FORWARD_DISTANCE = 1000
  DEFAULT_OUT_OF_ORDER_TOLERANCE = 100

  # 9.1: a hash ratchet over one leaf's secret. Each generation yields a key and nonce once and
  # steps the secret forward; per 9.2 neither the secret nor the key is kept once handed out.
  # When a receiver skips ahead, the keys of the generations it skipped are kept (at most
  # out_of_order_tolerance of them, oldest dropped first) so that late messages still decrypt (9.1, 15.3).
  class Ratchet
    attr_reader :next_generation, :max_forward_distance, :out_of_order_tolerance

    def initialize(suite, secret, max_forward_distance: DEFAULT_MAX_FORWARD_DISTANCE, out_of_order_tolerance: DEFAULT_OUT_OF_ORDER_TOLERANCE)
      @suite = suite
      @secret = secret
      @next_generation = 0
      @skipped = {} # generation -> [key, nonce], in increasing generation order
      @max_forward_distance = max_forward_distance
      @out_of_order_tolerance = out_of_order_tolerance
    end

    # generations below next_generation whose keys are still held
    def skipped_generations
      @skipped.keys
    end

    # derive the key and nonce of the current generation and step the ratchet
    def ratchet
      generation = @next_generation
      nonce = Melos::Crypto.derive_tree_secret(@suite, @secret, "nonce", generation, @suite.hpke.n_n)
      key   = Melos::Crypto.derive_tree_secret(@suite, @secret, "key",   generation, @suite.hpke.n_k)
      @secret = Melos::Crypto.derive_tree_secret(@suite, @secret, "secret", generation, @suite.kdf.n_h)
      @next_generation += 1
      [key, nonce, generation]
    end

    # the key and nonce of the given generation, ratcheting forward as needed. An earlier generation
    # is served once from the skipped keys; one that was already used, or dropped from the window,
    # cannot be derived again (StateError). A jump further than max_forward_distance is refused (ProtocolError).
    def ratchet_until(generation)
      if generation < @next_generation
        key_and_nonce = @skipped.delete(generation)
        return [*key_and_nonce, generation] if key_and_nonce
        raise Melos::StateError.new("generation #{generation} has already been consumed or is no longer kept (next generation is #{@next_generation})")
      end
      if generation - @next_generation > @max_forward_distance
        raise Melos::ProtocolError.new("generation #{generation} is more than #{@max_forward_distance} ahead of #{@next_generation}")
      end
      while @next_generation < generation
        key, nonce, skipped = ratchet
        @skipped[skipped] = [key, nonce]
      end
      @skipped.shift while @skipped.size > @out_of_order_tolerance
      ratchet
    end
  end

  attr_reader :suite, :n_leaves

  # options: max_forward_distance:, out_of_order_tolerance: for every ratchet (see Ratchet)
  def initialize(suite, n_leaves, encryption_secret, **options)
    @suite = suite
    @n_leaves = n_leaves
    @options = options
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
    ratchets[leaf_index] or raise Melos::ProtocolError.new("no leaf #{leaf_index} in secret tree with #{@n_leaves} leaves")
  end

  private

  # 9: derive the secrets of the subtree under node_index down to the leaves
  def populate(node_index, secret)
    if Melos::Tree.leaf?(node_index)
      leaf_index = node_index / 2
      @handshake_ratchets[leaf_index]   = Ratchet.new(@suite, Melos::Crypto.expand_with_label(@suite, secret, "handshake",   "", @suite.kdf.n_h), **@options)
      @application_ratchets[leaf_index] = Ratchet.new(@suite, Melos::Crypto.expand_with_label(@suite, secret, "application", "", @suite.kdf.n_h), **@options)
    else
      left_secret  = Melos::Crypto.expand_with_label(@suite, secret, "tree", "left",  @suite.kdf.n_h)
      right_secret = Melos::Crypto.expand_with_label(@suite, secret, "tree", "right", @suite.kdf.n_h)
      populate(Melos::Tree.left(node_index),  left_secret)
      populate(Melos::Tree.right(node_index), right_secret)
    end
  end
end
