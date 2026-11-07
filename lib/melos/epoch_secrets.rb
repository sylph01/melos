require_relative 'crypto'
require_relative 'secret_tree'

# The key schedule (RFC 9420 Section 8) for one epoch: the epoch_secret and the secrets
# derived from it (Table 4), the joiner and PSK secrets that produced it (needed to build
# a Welcome, 12.4.3.1), and the epoch's secret tree (Section 9).
#
# A new epoch comes from #next with the commit secret, PSK secret and new GroupContext,
# which uses this epoch's init_secret as Section 8 describes.
class Melos::EpochSecrets
  attr_reader :suite, :epoch_secret, :joiner_secret, :psk_secret, :n_leaves

  # Table 4, plus init_secret which is derived the same way
  DERIVED_SECRETS = {
    sender_data_secret:  'sender data',
    encryption_secret:   'encryption',
    exporter_secret:     'exporter',
    external_secret:     'external',
    confirmation_key:    'confirm',
    membership_key:      'membership',
    resumption_psk:      'resumption',
    epoch_authenticator: 'authentication',
    init_secret:         'init'
  }.freeze

  DERIVED_SECRETS.each do |name, label|
    define_method(name) do
      @derived[name] ||= Melos::Crypto.derive_secret(@suite, require_epoch_secret(name), label)
    end
  end

  # derived: secrets known without an epoch_secret (see .from_init_secret and .from_components)
  def initialize(suite, epoch_secret: nil, joiner_secret: nil, psk_secret: nil, n_leaves: nil, derived: {})
    unknown = derived.keys - DERIVED_SECRETS.keys
    raise ArgumentError.new("unknown secrets: #{unknown.join(', ')}") unless unknown.empty?
    @suite = suite
    @epoch_secret = epoch_secret
    @joiner_secret = joiner_secret
    @psk_secret = psk_secret
    @n_leaves = n_leaves
    @derived = derived.dup
  end

  def self.from_epoch_secret(suite, epoch_secret, n_leaves: nil)
    new(suite, epoch_secret: epoch_secret, n_leaves: n_leaves)
  end

  # 8: epoch_secret = ExpandWithLabel(Extract(joiner_secret, psk_secret), "epoch", GroupContext)
  # This is how a new member joins an epoch from a Welcome (12.4.3.1).
  def self.from_joiner(suite, joiner_secret, psk_secret, group_context, n_leaves: nil)
    member_secret = Melos::Crypto.kdf_extract(suite, joiner_secret, psk_secret)
    epoch_secret = Melos::Crypto.expand_with_label(suite, member_secret, "epoch", group_context.raw, suite.kdf.n_h)
    new(suite, epoch_secret: epoch_secret, joiner_secret: joiner_secret, psk_secret: psk_secret, n_leaves: n_leaves)
  end

  # 8: the state before an epoch exists, when only init_secret is known (a fresh random
  # value for a new group). Only #next is meaningful on it.
  def self.from_init_secret(suite, init_secret)
    new(suite, derived: { init_secret: init_secret })
  end

  # an epoch given by some of its derived secrets rather than by epoch_secret; for test vectors
  def self.from_components(suite, n_leaves: nil, **secrets)
    new(suite, n_leaves: n_leaves, derived: secrets)
  end

  # 8: welcome_secret = DeriveSecret(Extract(joiner_secret, psk_secret), "welcome")
  def self.welcome_secret(suite, joiner_secret, psk_secret)
    Melos::Crypto.derive_secret(suite, Melos::Crypto.kdf_extract(suite, joiner_secret, psk_secret), "welcome")
  end

  # 12.4.3.1: the key and nonce that encrypt the GroupInfo in a Welcome
  def self.welcome_key_and_nonce(suite, joiner_secret, psk_secret)
    ws = welcome_secret(suite, joiner_secret, psk_secret)
    [
      Melos::Crypto.expand_with_label(suite, ws, "key",   "", suite.hpke.n_k),
      Melos::Crypto.expand_with_label(suite, ws, "nonce", "", suite.hpke.n_n)
    ]
  end

  def welcome_secret
    self.class.welcome_secret(@suite, require_joiner_secret(:welcome_secret), @psk_secret)
  end

  def welcome_key_and_nonce
    self.class.welcome_key_and_nonce(@suite, require_joiner_secret(:welcome_key_and_nonce), @psk_secret)
  end

  # 8: the next epoch. joiner_secret = ExpandWithLabel(Extract(init_secret, commit_secret), "joiner", GroupContext)
  #   n_leaves: leaf count of the ratchet tree in the new epoch, for its secret tree
  def next(commit_secret, psk_secret, group_context, n_leaves: @n_leaves)
    joiner_secret = Melos::Crypto.expand_with_label(
      @suite, Melos::Crypto.kdf_extract(@suite, init_secret, commit_secret), "joiner", group_context.raw, @suite.kdf.n_h
    )
    self.class.from_joiner(@suite, joiner_secret, psk_secret, group_context, n_leaves: n_leaves)
  end

  # 9: this epoch's secret tree, built on first use
  def secret_tree
    raise ArgumentError.new('n_leaves is needed to build the secret tree') if @n_leaves.nil?
    @secret_tree ||= Melos::SecretTree.new(@suite, @n_leaves, encryption_secret)
  end

  private

  def require_epoch_secret(name)
    @epoch_secret or raise ArgumentError.new("#{name} is not available: this epoch has no epoch_secret")
  end

  def require_joiner_secret(name)
    @joiner_secret or raise ArgumentError.new("#{name} is not available: this epoch has no joiner_secret")
  end
end
