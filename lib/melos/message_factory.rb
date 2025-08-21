require_relative 'struct/structs'
require_relative 'group_state'
require_relative 'crypto'
require_relative 'util'

module Melos
  # Factory for creating MLS messages according to RFC 9420
  # Handles the complete message creation pipeline from content to wire format
  class MessageFactory
    include Melos::Util

    # Create an application message (Section 15 of RFC 9420)
    # Returns an MLSMessage containing a PrivateMessage
    def self.create_application_message(
      group_state:,
      application_data:,
      authenticated_data: '',
      padding_size: 0
    )
      group_state.validate_for_message_creation!

      # Create sender
      sender = group_state.create_sender

      # Create FramedContent
      framed_content = Melos::Struct::FramedContent.create(
        group_id: group_state.group_id,
        epoch: group_state.epoch,
        sender: sender,
        authenticated_data: authenticated_data,
        content_type: Melos::Constants::ContentType::APPLICATION,
        content: application_data
      )

      # Create AuthenticatedContent (will be signed later)
      auth_data = Melos::Struct::FramedContentAuthData.create_signature_auth(
        signature: '', # Will be filled by signing
        content_type: Melos::Constants::ContentType::APPLICATION
      )

      authenticated_content = Melos::Struct::AuthenticatedContent.create(
        wire_format: Melos::Constants::WireFormat::MLS_PRIVATE_MESSAGE,
        content: framed_content,
        auth: auth_data
      )

      # Sign the authenticated content
      authenticated_content.sign!(group_state.cipher_suite, group_state.signature_private_key, group_state.group_context)

      # Create PrivateMessageContent
      private_content = Melos::Struct::PrivateMessageContent.create_application(
        application_data: application_data,
        auth: authenticated_content.auth,
        padding_size: padding_size
      )

      # Protect as PrivateMessage
      private_message = Melos::Struct::PrivateMessage.protect(
        authenticated_content,
        group_state.cipher_suite,
        group_state.secret_tree,
        group_state.secret_tree.sender_data_secret(group_state.leaf_index),
        padding_size
      )

      # Wrap in MLSMessage
      Melos::Struct::MLSMessage.create_private_message(private_message: private_message)
    end

    # Create a proposal message (Section 12.1 of RFC 9420)
    # Returns an MLSMessage containing a PublicMessage
    def self.create_proposal_message(
      group_state:,
      proposal:,
      authenticated_data: ''
    )
      group_state.validate_for_message_creation!

      # Create sender
      sender = group_state.create_sender

      # Create FramedContent
      framed_content = Melos::Struct::FramedContent.create(
        group_id: group_state.group_id,
        epoch: group_state.epoch,
        sender: sender,
        authenticated_data: authenticated_data,
        content_type: Melos::Constants::ContentType::PROPOSAL,
        content: proposal
      )

      # Create AuthenticatedContent
      auth_data = Melos::Struct::FramedContentAuthData.create_signature_auth(
        signature: '', # Will be filled by signing
        content_type: Melos::Constants::ContentType::PROPOSAL
      )

      authenticated_content = Melos::Struct::AuthenticatedContent.create(
        wire_format: Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE,
        content: framed_content,
        auth: auth_data
      )

      # Sign the authenticated content
      authenticated_content.sign!(group_state.cipher_suite, group_state.signature_private_key, group_state.group_context)

      # Protect as PublicMessage
      public_message = Melos::Struct::PublicMessage.protect(
        authenticated_content,
        group_state.cipher_suite,
        group_state.membership_key,
        group_state.group_context
      )

      # Wrap in MLSMessage
      Melos::Struct::MLSMessage.create_public_message(public_message: public_message)
    end

    # Create a commit message (Section 12.4 of RFC 9420)
    # Returns an MLSMessage containing a PublicMessage
    def self.create_commit_message(
      group_state:,
      proposals:,
      authenticated_data: '',
      path: nil
    )
      group_state.validate_for_message_creation!

      # Create commit structure
      commit = Melos::Struct::Commit.create(
        proposals: proposals,
        path: path
      )

      # Create sender
      sender = group_state.create_sender

      # Create FramedContent
      framed_content = Melos::Struct::FramedContent.create(
        group_id: group_state.group_id,
        epoch: group_state.epoch,
        sender: sender,
        authenticated_data: authenticated_data,
        content_type: Melos::Constants::ContentType::COMMIT,
        content: commit
      )

      # Create AuthenticatedContent with confirmation tag placeholder
      auth_data = Melos::Struct::FramedContentAuthData.create_signature_auth(
        signature: '', # Will be filled by signing
        content_type: Melos::Constants::ContentType::COMMIT,
        confirmation_tag: '' # Will be computed based on new group state
      )

      authenticated_content = Melos::Struct::AuthenticatedContent.create(
        wire_format: Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE,
        content: framed_content,
        auth: auth_data
      )

      # Sign the authenticated content
      authenticated_content.sign!(group_state.cipher_suite, group_state.signature_private_key, group_state.group_context)

      # Protect as PublicMessage
      public_message = Melos::Struct::PublicMessage.protect(
        authenticated_content,
        group_state.cipher_suite,
        group_state.membership_key,
        group_state.group_context
      )

      # Wrap in MLSMessage
      Melos::Struct::MLSMessage.create_public_message(public_message: public_message)
    end
  end
end
