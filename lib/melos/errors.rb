module Melos
  # Base class of everything melos raises on purpose. Plain ArgumentError is still used for
  # mistakes in how the library is called (wrong object type, missing option, internal misuse).
  class Error < StandardError; end

  # Input that RFC 9420 says MUST be rejected: a malformed encoding, a signature, MAC or hash that
  # does not verify, a proposal or commit that breaks the protocol's rules, a tree that fails its
  # integrity checks. The message is not to be acted on.
  class ProtocolError < Error; end

  # An operation this group or client cannot perform in its current state: sending after being
  # removed, sending application data while proposals are pending, a PSK or key we do not hold,
  # a group_id already in use.
  class StateError < Error; end

  # A part of RFC 9420 this implementation does not provide yet. See docs/roadmap.md.
  class UnsupportedError < Error; end
end
