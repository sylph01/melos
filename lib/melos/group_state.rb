require_relative 'struct/structs'

module Melos
  # Represents the state of an MLS group for a particular member
  # Used for creating and processing messages according to RFC 9420
  class GroupState
    attr_reader :group_context, :tree, :key_schedule, :secret_tree
    attr_reader :membership_key, :signature_private_key, :leaf_index

    def initialize(
      group_context:,
      tree:,
      key_schedule:,
      secret_tree:,
      membership_key:,
      signature_private_key:,
      leaf_index:
    )
      @group_context = group_context
      @tree = tree
      @key_schedule = key_schedule
      @secret_tree = secret_tree
      @membership_key = membership_key
      @signature_private_key = signature_private_key
      @leaf_index = leaf_index
    end

    # Convenience methods for accessing group context fields
    def epoch
      @group_context.epoch
    end

    def group_id
      @group_context.group_id
    end

    def cipher_suite
      @group_context.cipher_suite
    end

    def version
      @group_context.version
    end

    def tree_hash
      @group_context.tree_hash
    end

    def confirmed_transcript_hash
      @group_context.confirmed_transcript_hash
    end

    def extensions
      @group_context.extensions
    end

    # Create a sender object for this group member
    def create_sender
      Melos::Struct::Sender.create_member(@leaf_index)
    end

    # Get the current generation for secret tree encryption
    def current_generation
      @secret_tree.current_generation
    end

    # Validate that this group state can create messages
    def validate_for_message_creation!
      raise "Group context is required" unless @group_context
      raise "Tree is required" unless @tree
      raise "Key schedule is required" unless @key_schedule
      raise "Secret tree is required" unless @secret_tree
      raise "Membership key is required" unless @membership_key
      raise "Signature private key is required" unless @signature_private_key
      raise "Leaf index is required" unless @leaf_index
    end
  end
end
