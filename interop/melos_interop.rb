$LOAD_PATH.unshift(File.join(__dir__, 'proto'))
require 'grpc'
require 'mls_client_services_pb'
require 'melos'

module Melos
  # The MLSClient gRPC service of the mls-implementations interop harness
  # (https://github.com/mlswg/mls-implementations/tree/main/interop), backed by Melos::Client and
  # Melos::Group. The test runner drives it through integer handles:
  #   state_id       a member's view of a group (State)
  #   transaction_id a published KeyPackage waiting for its Welcome (Join)
  #   reinit_id      a member of a reinitialized group with its KeyPackage for the successor (ReInit)
  #   signer_id      an external sender (Melos::ExternalSender)
  # Every RPC that fails raises GRPC::Aborted with the error's class and message.
  module Interop
    CIPHER_SUITES = (1..7).to_a.freeze

    # encrypt: handshake messages go out as PrivateMessages
    # sent: the bytes of proposals this member sent in the current epoch, which the test runner passes
    #       back to it alongside other members' proposals and which it must not process again
    # pending: the CommitResult of a commit this member created and has not merged yet
    State = ::Struct.new(:client, :group, :encrypt, :sent, :pending, keyword_init: true)
    Join = ::Struct.new(:client, :bundle, keyword_init: true)
    ReInit = ::Struct.new(:old_group, :client, :bundle, :encrypt, keyword_init: true)

    class Service < MlsClient::MLSClient::Service
      def initialize(log: $stderr)
        super()
        @log = log
        @next_id = 0
        @states = {}
        @joins = {}
        @reinits = {}
        @signers = {}
        @lock = Mutex.new
      end

      # every RPC runs under one lock (the runner calls one at a time anyway) and turns errors into gRPC statuses
      def self.rpc_method(name, &body)
        define_method(name) do |request, _call|
          @lock.synchronize do
            instance_exec(request, &body)
          rescue GRPC::BadStatus
            raise
          rescue StandardError => e
            @log&.puts "[melos-interop] #{name} failed: #{e.class}: #{e.message}"
            @log&.puts e.backtrace.first(5).map { "    #{_1}" } if ENV['MELOS_INTEROP_DEBUG']
            raise GRPC::Aborted.new("#{e.class}: #{e.message}")
          end
        end
      end

      ## Information about the client

      rpc_method(:name) { |_req| MlsClient::NameResponse.new(name: "melos #{Melos::VERSION}") }
      rpc_method(:supported_ciphersuites) { |_req| MlsClient::SupportedCiphersuitesResponse.new(ciphersuites: CIPHER_SUITES) }

      ## Ways to become a member of a group

      rpc_method(:create_group) do |req|
        client = Melos::Client.new(req.cipher_suite, identity: req.identity.b)
        group = client.create_group(req.group_id.b)
        MlsClient::CreateGroupResponse.new(state_id: store_state(client, group, req.encrypt_handshake))
      end

      rpc_method(:create_key_package) do |req|
        client = Melos::Client.new(req.cipher_suite, identity: req.identity.b)
        bundle = client.create_key_package
        MlsClient::CreateKeyPackageResponse.new(
          transaction_id: store(@joins, Join.new(client: client, bundle: bundle)), key_package: bundle.message.raw,
          init_priv: bundle.init_private_key, encryption_priv: bundle.encryption_private_key, signature_priv: client.signature_private_key
        )
      end

      rpc_method(:join_group) do |req|
        join = fetch(@joins, req.transaction_id, 'transaction')
        group = join.client.join_group(message(req.welcome), ratchet_tree: optional(req.ratchet_tree))
        @joins.delete(req.transaction_id)
        MlsClient::JoinGroupResponse.new(state_id: store_state(join.client, group, req.encrypt_handshake), epoch_authenticator: group.epoch_authenticator)
      end

      rpc_method(:external_join) do |req|
        group_info = message(req.group_info)
        suite = group_info.group_info.group_context.cipher_suite
        client = Melos::Client.new(suite, identity: req.identity.b)
        req.psks.each { client.add_external_psk(_1.psk_id.b, _1.psk_secret.b) }
        remove = nil
        if req.remove_prior
          tree = Melos::RatchetTree.parse(Melos::Crypto::CipherSuite.new(suite), optional(req.ratchet_tree) || ratchet_tree_extension(group_info.group_info))
          remove = find_member(tree, req.identity.b)
        end
        group, commit = client.join_by_external_commit(group_info, ratchet_tree: optional(req.ratchet_tree), remove: remove,
                                                                   psk_ids: req.psks.map { _1.psk_id.b })
        MlsClient::ExternalJoinResponse.new(state_id: store_state(client, group, req.encrypt_handshake), commit: commit.raw,
                                            epoch_authenticator: group.epoch_authenticator)
      end

      ## Operations using a group state

      rpc_method(:group_info) do |req|
        state = state(req.state_id)
        MlsClient::GroupInfoResponse.new(
          group_info: state.group.group_info(external_pub: true, include_ratchet_tree: !req.external_tree).raw,
          ratchet_tree: req.external_tree ? state.group.ratchet_tree.raw : ''
        )
      end

      rpc_method(:state_auth) { |req| MlsClient::StateAuthResponse.new(state_auth_secret: state(req.state_id).group.epoch_authenticator) }

      rpc_method(:export) do |req|
        MlsClient::ExportResponse.new(exported_secret: state(req.state_id).group.export_secret(req.label.b, req.context.b, req.key_length))
      end

      rpc_method(:protect) do |req|
        message = state(req.state_id).group.create_application_message(req.plaintext.b, authenticated_data: req.authenticated_data.b)
        MlsClient::ProtectResponse.new(ciphertext: message.raw)
      end

      rpc_method(:unprotect) do |req|
        content = state(req.state_id).group.unprotect(message(req.ciphertext)).content
        raise ArgumentError.new('not an application message') unless content.content_type == Melos::Constants::ContentType::APPLICATION
        MlsClient::UnprotectResponse.new(authenticated_data: content.authenticated_data, plaintext: content.application_data)
      end

      rpc_method(:store_psk) do |req|
        holder = @states[req.state_or_transaction_id] || @joins[req.state_or_transaction_id] or
          raise ArgumentError.new("unknown state or transaction #{req.state_or_transaction_id}")
        holder.client.add_external_psk(req.psk_id.b, req.psk_secret.b)
        MlsClient::StorePSKResponse.new
      end

      ## Proposals

      rpc_method(:add_proposal) { |req| send_proposal(req.state_id) { |group, options| group.create_add_proposal(message(req.key_package), **options) } }
      rpc_method(:update_proposal) { |req| send_proposal(req.state_id) { |group, options| group.create_update_proposal(**options) } }
      rpc_method(:remove_proposal) do |req|
        send_proposal(req.state_id) { |group, options| group.create_remove_proposal(find_member(group.ratchet_tree, req.removed_id.b), **options) }
      end
      rpc_method(:external_psk_proposal) { |req| send_proposal(req.state_id) { |group, options| group.create_psk_proposal(req.psk_id.b, **options) } }
      rpc_method(:resumption_psk_proposal) do |req|
        send_proposal(req.state_id) { |group, options| group.create_resumption_psk_proposal(req.epoch_id, **options) }
      end
      rpc_method(:group_context_extensions_proposal) do |req|
        send_proposal(req.state_id) { |group, options| group.create_proposal(gce_proposal(extensions(req.extensions)), **options) }
      end
      rpc_method(:re_init_proposal) do |req|
        send_proposal(req.state_id) do |group, options|
          group.create_reinit_proposal(group_id: req.group_id.b, cipher_suite: req.cipher_suite, extensions: extensions(req.extensions), **options)
        end
      end

      ## Commits

      rpc_method(:commit) { |req| do_commit(req) }
      rpc_method(:handle_commit) { |req| do_handle_commit(req) }

      rpc_method(:handle_pending_commit) do |req|
        state = state(req.state_id)
        merge_pending(state)
        MlsClient::HandleCommitResponse.new(state_id: req.state_id, epoch_authenticator: state.group.epoch_authenticator)
      end

      ## Reinitialization (11.2)

      rpc_method(:re_init_commit) { |req| do_commit(req) }

      rpc_method(:handle_pending_re_init_commit) do |req|
        state = state(req.state_id)
        merge_pending(state)
        reinit_response(state)
      end

      rpc_method(:handle_re_init_commit) do |req|
        state = state(req.state_id)
        do_handle_commit(req)
        reinit_response(state)
      end

      rpc_method(:re_init_welcome) do |req|
        reinit = fetch(@reinits, req.reinit_id, 'reinit')
        group, welcome = reinit.client.reinit_group(reinit.old_group, req.key_package.map { message(_1) },
                                                    path: req.force_path ? :always : :if_required, include_ratchet_tree: !req.external_tree)
        @reinits.delete(req.reinit_id)
        subgroup_response(reinit.client, group, welcome, reinit.encrypt, req.external_tree)
      end

      rpc_method(:handle_re_init_welcome) do |req|
        reinit = fetch(@reinits, req.reinit_id, 'reinit')
        group = reinit.client.join_group(message(req.welcome), ratchet_tree: optional(req.ratchet_tree), resumed_groups: [reinit.old_group])
        @reinits.delete(req.reinit_id)
        MlsClient::JoinGroupResponse.new(state_id: store_state(reinit.client, group, reinit.encrypt), epoch_authenticator: group.epoch_authenticator)
      end

      ## Subgroup branching (11.3)

      rpc_method(:create_branch) do |req|
        state = state(req.state_id)
        group, welcome = state.client.branch_group(
          state.group, req.key_packages.map { message(_1) }, group_id: req.group_id.b, extensions: extensions(req.extensions),
          path: req.force_path ? :always : :if_required, include_ratchet_tree: !req.external_tree
        )
        subgroup_response(state.client, group, welcome, state.encrypt, req.external_tree)
      end

      rpc_method(:handle_branch) do |req|
        state = state(req.state_id)
        join = fetch(@joins, req.transaction_id, 'transaction')
        group = join.client.join_group(message(req.welcome), ratchet_tree: optional(req.ratchet_tree), resumed_groups: [state.group])
        @joins.delete(req.transaction_id)
        MlsClient::HandleBranchResponse.new(state_id: store_state(join.client, group, state.encrypt), epoch_authenticator: group.epoch_authenticator)
      end

      ## External proposals (12.1.8)

      rpc_method(:new_member_add_proposal) do |req|
        context = message(req.group_info).group_info.group_context
        client = Melos::Client.new(context.cipher_suite, identity: req.identity.b)
        proposal, bundle = client.create_new_member_proposal(group_id: context.group_id, epoch: context.epoch)
        MlsClient::NewMemberAddProposalResponse.new(
          transaction_id: store(@joins, Join.new(client: client, bundle: bundle)), proposal: proposal.raw,
          init_priv: bundle.init_private_key, encryption_priv: bundle.encryption_private_key, signature_priv: client.signature_private_key
        )
      end

      rpc_method(:create_external_signer) do |req|
        signer = Melos::ExternalSender.new(req.cipher_suite, identity: req.identity.b)
        MlsClient::CreateExternalSignerResponse.new(signer_id: store(@signers, signer), external_sender: signer.external_sender.raw)
      end

      # a GroupContextExtensions proposal adding the signer to the external_senders extension
      rpc_method(:add_external_signer) do |req|
        send_proposal(req.state_id) do |group, options|
          senders = group.external_senders + [Melos::Struct::ExternalSender.new(req.external_sender.b)]
          others = group.extensions.reject { _1.extension_type == Melos::Constants::ExtensionType::EXTERNAL_SENDERS }
          group.create_proposal(gce_proposal(others + [Melos::Struct::ExternalSenders.extension(senders)]), **options)
        end
      end

      rpc_method(:external_signer_proposal) do |req|
        signer = fetch(@signers, req.signer_id, 'signer')
        info = message(req.group_info).group_info
        context = info.group_context
        senders = context.extensions.find { _1.extension_type == Melos::Constants::ExtensionType::EXTERNAL_SENDERS }
        index = senders && Melos::Struct::ExternalSenders.new(senders.extension_data).external_senders.index { _1.signature_key == signer.signature_public_key }
        raise ArgumentError.new('this signer is not in the group\'s external_senders') if index.nil?
        tree = Melos::RatchetTree.parse(signer.suite, optional(req.ratchet_tree) || ratchet_tree_extension(info))
        proposal = proposal_from_description(req.description, suite: signer.suite, group_id: context.group_id, tree: tree)
        message = signer.create_proposal(proposal, group_id: context.group_id, epoch: context.epoch, sender_index: index)
        MlsClient::ProposalResponse.new(proposal: message.raw)
      end

      rpc_method(:free) do |req|
        @states.delete(req.state_id)
        MlsClient::FreeResponse.new
      end

      private

      def store(table, value)
        @next_id += 1
        table[@next_id] = value
        @next_id
      end

      def store_state(client, group, encrypt)
        store(@states, State.new(client: client, group: group, encrypt: encrypt, sent: [], pending: nil))
      end

      def fetch(table, id, what)
        table.fetch(id) { raise ArgumentError.new("unknown #{what} #{id}") }
      end

      def state(id)
        fetch(@states, id, 'state')
      end

      def message(bytes)
        Melos::Struct::MLSMessage.new(bytes.b)
      end

      def optional(bytes)
        bytes.nil? || bytes.empty? ? nil : bytes.b
      end

      def wire_format(state)
        state.encrypt ? Melos::Constants::WireFormat::MLS_PRIVATE_MESSAGE : Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE
      end

      def ratchet_tree_extension(group_info)
        group_info.extensions.find { _1.extension_type == Melos::Constants::ExtensionType::RATCHET_TREE }&.extension_data or
          raise ArgumentError.new('no ratchet tree given')
      end

      # the leaf whose basic credential carries identity (the test runner names members by identity)
      def find_member(tree, identity)
        tree.find_leaf_index { _1.credential.credential_type == Melos::Constants::CredentialType::BASIC && _1.credential.identity.b == identity } or
          raise ArgumentError.new("no member with identity #{identity.inspect}")
      end

      def extensions(list)
        list.map { Melos::Struct::Extension.create(extension_type: _1.extension_type, extension_data: _1.extension_data.b) }
      end

      def gce_proposal(extensions)
        Melos::Struct::Proposal.create(
          proposal_type: Melos::Constants::ProposalType::GROUP_CONTEXT_EXTENSIONS,
          group_context_extensions: Melos::Struct::GroupContextExtensions.create(extensions: extensions)
        )
      end

      # a proposal from the runner's ProposalDescription (by-value proposals in Commit, external signers' proposals)
      def proposal_from_description(description, suite:, group_id:, tree:)
        type = Melos::Constants::ProposalType
        case description.proposal_type
        when 'add'
          Melos::Struct::Proposal.create(proposal_type: type::ADD, add: Melos::Struct::Add.create(key_package: message(description.key_package).key_package))
        when 'remove'
          Melos::Struct::Proposal.create(proposal_type: type::REMOVE, remove: Melos::Struct::Remove.create(removed: find_member(tree, description.removed_id.b)))
        when 'externalPSK'
          psk_id = Melos::Struct::PreSharedKeyID.create_external(psk_id: description.psk_id.b, psk_nonce: SecureRandom.random_bytes(suite.kdf.n_h))
          Melos::Struct::Proposal.create(proposal_type: type::PSK, psk: Melos::Struct::PreSharedKey.create(psk: psk_id))
        when 'resumptionPSK'
          psk_id = Melos::Struct::PreSharedKeyID.create_resumption(
            usage: Melos::Constants::ResumptionPSKUsage::APPLICATION, psk_group_id: group_id, psk_epoch: description.epoch_id,
            psk_nonce: SecureRandom.random_bytes(suite.kdf.n_h)
          )
          Melos::Struct::Proposal.create(proposal_type: type::PSK, psk: Melos::Struct::PreSharedKey.create(psk: psk_id))
        when 'groupContextExtensions'
          gce_proposal(extensions(description.extensions))
        when 'reinit'
          reinit = Melos::Struct::ReInit.create(group_id: description.group_id.b, version: Melos::Constants::Version::MLS10,
                                                cipher_suite: description.cipher_suite, extensions: extensions(description.extensions))
          Melos::Struct::Proposal.create(proposal_type: type::REINIT, reinit: reinit)
        else
          raise ArgumentError.new("unknown proposal type #{description.proposal_type.inspect}")
        end
      end

      def send_proposal(state_id)
        state = state(state_id)
        message = yield(state.group, { wire_format: wire_format(state) })
        state.sent << message.raw
        MlsClient::ProposalResponse.new(proposal: message.raw)
      end

      # proposals the runner hands over, except those this member sent itself
      def process_proposals(state, proposals)
        proposals.each do |bytes|
          next if state.sent.include?(bytes.b)
          state.group.process_message(message(bytes))
        end
      end

      def do_commit(req)
        state = state(req.state_id)
        process_proposals(state, req.by_reference)
        inline = req.by_value.map { proposal_from_description(_1, suite: state.group.suite, group_id: state.group.group_id, tree: state.group.ratchet_tree) }
        result = state.group.create_commit(
          inline_proposals: inline, wire_format: wire_format(state), include_ratchet_tree: !req.external_tree,
          path: req.force_path ? :always : :if_required
        )
        state.pending = result
        MlsClient::CommitResponse.new(commit: result.commit.raw, welcome: result.welcome&.raw || '',
                                      ratchet_tree: req.external_tree ? result.staged.ratchet_tree.raw : '')
      end

      def merge_pending(state)
        raise ArgumentError.new('no pending commit') if state.pending.nil?
        state.group.merge_commit(state.pending.staged)
        state.pending = nil
        state.sent = []
      end

      def do_handle_commit(req)
        state = state(req.state_id)
        if state.pending && state.pending.commit.raw == req.commit.b
          merge_pending(state)
        else
          state.pending = nil
          process_proposals(state, req.proposal)
          state.group.process_message(message(req.commit))
          state.sent = []
        end
        MlsClient::HandleCommitResponse.new(state_id: req.state_id, epoch_authenticator: state.group.epoch_authenticator)
      end

      # 11.2: once the ReInit is merged, a client of the new suite publishes a KeyPackage for the successor group
      def reinit_response(state)
        group = state.group
        reinit = group.pending_reinit or raise ArgumentError.new('the commit did not reinitialize the group')
        client = Melos::Client.new(reinit.cipher_suite, credential: state.client.credential)
        state.client.external_psks.each { |id, psk| client.add_external_psk(id, psk) }
        bundle = client.create_key_package
        id = store(@reinits, ReInit.new(old_group: group, client: client, bundle: bundle, encrypt: state.encrypt))
        MlsClient::HandleReInitCommitResponse.new(reinit_id: id, key_package: bundle.message.raw, epoch_authenticator: group.epoch_authenticator)
      end

      def subgroup_response(client, group, welcome, encrypt, external_tree)
        MlsClient::CreateSubgroupResponse.new(
          state_id: store_state(client, group, encrypt), welcome: welcome.raw,
          ratchet_tree: external_tree ? group.ratchet_tree.raw : '', epoch_authenticator: group.epoch_authenticator
        )
      end
    end

    # serve on 0.0.0.0:port until interrupted
    def self.serve(port, log: $stderr)
      server = GRPC::RpcServer.new
      server.add_http2_port("0.0.0.0:#{port}", :this_port_is_insecure)
      server.handle(Service.new(log: log))
      log&.puts "[melos-interop] listening on port #{port}"
      server.run_till_terminated_or_interrupted(%w[INT TERM])
    end
  end
end
