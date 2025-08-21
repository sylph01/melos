require_relative 'struct/structs'

module Melos
  # Factory for creating MLS proposal messages according to RFC 9420 Section 12.1
  # Provides convenience methods for creating different types of proposals
  class ProposalFactory
    # Create an Add proposal (Section 12.1.1)
    def self.create_add_proposal(key_package:)
      add = Melos::Struct::Add.create(key_package: key_package)
      Melos::Struct::Proposal.create_add(add: add)
    end

    # Create an Update proposal (Section 12.1.2)
    def self.create_update_proposal(leaf_node:)
      update = Melos::Struct::Update.create(leaf_node: leaf_node)
      Melos::Struct::Proposal.create_update(update: update)
    end

    # Create a Remove proposal (Section 12.1.3)
    def self.create_remove_proposal(removed_leaf_index:)
      remove = Melos::Struct::Remove.create(removed: removed_leaf_index)
      Melos::Struct::Proposal.create_remove(remove: remove)
    end

    # Create a PreSharedKey proposal (Section 12.1.4)
    def self.create_psk_proposal(psk_id:, psk_nonce:)
      psk = Melos::Struct::PreSharedKeyID.create_external(
        psk_id: psk_id,
        psk_nonce: psk_nonce
      )
      psk_struct = Melos::Struct::PreSharedKey.create(psk: psk)
      Melos::Struct::Proposal.create_psk(psk: psk_struct)
    end

    # Create a ReInit proposal (Section 12.1.5)
    def self.create_reinit_proposal(group_id:, version:, cipher_suite:, extensions: [])
      reinit = Melos::Struct::ReInit.create(
        group_id: group_id,
        version: version,
        cipher_suite: cipher_suite,
        extensions: extensions
      )
      Melos::Struct::Proposal.create_reinit(reinit: reinit)
    end

    # Create an ExternalInit proposal (Section 12.1.6)
    def self.create_external_init_proposal(kem_output:)
      external_init = Melos::Struct::ExternalInit.create(kem_output: kem_output)
      Melos::Struct::Proposal.create_external_init(external_init: external_init)
    end

    # Create a GroupContextExtensions proposal (Section 12.1.7)
    def self.create_group_context_extensions_proposal(extensions:)
      gce = Melos::Struct::GroupContextExtensions.create(extensions: extensions)
      Melos::Struct::Proposal.create_group_context_extensions(group_context_extensions: gce)
    end

    # Helper method to create a ProposalOrRef from a proposal
    def self.create_proposal_or_ref_from_proposal(proposal:)
      Melos::Struct::ProposalOrRef.create(
        type: Melos::Constants::ProposalOrRefType::PROPOSAL,
        proposal: proposal
      )
    end

    # Helper method to create a ProposalOrRef from a reference
    def self.create_proposal_or_ref_from_reference(reference:)
      Melos::Struct::ProposalOrRef.create(
        type: Melos::Constants::ProposalOrRefType::REFERENCE,
        reference: reference
      )
    end
  end
end
