class Melos::Group
  attr_reader :group_id, :epoch, :tree_hash, :confirmed_transcript_hash, :confirmation_tag, :interim_transcript_hash
  def initialize(client, group_id)
    # TODO: check if cipher_suite is defined
    @cipher_suite = client.cipher_suite
    @group_id = group_id
    @epoch = 0
    @group_initialized = false
  end

  def init_group(node)
    if @group_initialized
      # do nothing
    else
      # single node, a leaf node containing an HPKE PK and credential for the creator
      @ratchet_tree = [node]
      @leaf_index = 0
      @tree_hash = Melos::Struct::RatchetTree.root_tree_hash(@cipher_suite, @ratchet_tree)
      @confirmed_transcript_hash = ''
      @epoch_secret = SecureRandom.random_bytes(@cipher_suite.kdf.n_h)
      @extensions = []
      # calculate interim transcript hash
      # TODO: separate this into a method
      confirmation_key = Melos::KeySchedule.confirmation_key(@cipher_suite, @epoch_secret)
      @confirmation_tag = Melos::Crypto.mac(@cipher_suite, confirmation_key, @confirmed_transcript_hash)
      @interim_transcript_hash = Melos::Crypto.hash(@cipher_suite,
        @confirmed_transcript_hash + Melos::Vec.string_to_vec(@confirmation_tag)
      )
      @group_initialized = true
    end
  end

  def group_context
    return nil if !@group_initialized
    Melos::Struct::GroupContext.create(
      cipher_suite: @cipher_suite.suite_id,
      group_id: @group_id,
      epoch: @epoch,
      tree_hash: @tree_hash,
      confirmed_transcript_hash: @confirmed_transcript_hash,
      extensions: @extensions
    )
  end
  
  def create_add_proposal(key_package, signature_private_key)
    add = Melos::Struct::Add.allocate
    add.key_package = key_package
    add_proposal = Melos::Struct::Proposal.allocate
    add_proposal.proposal_type = Melos::Constants::ProposalType::ADD
    add_proposal.add = add
    framed_content = Melos::Struct::FramedContent.create(
      group_id: @group_id,
      epoch: @epoch,
      sender: Melos::Struct::Sender.create_member(@leaf_index),
      authenticated_data: "authenticated_data", # 6.3.1: it is up to the application to decide what authenticated_data to provide and how much padding to add to a given message (if any)
      content_type: Melos::Constants::ContentType::PROPOSAL,
      content: add_proposal
    )
    authenticated_content = Melos::Struct::AuthenticatedContent.create(
      wire_format: Melos::Constants::WireFormat::MLS_PUBLIC_MESSAGE,
      content: framed_content,
      auth: nil
    )
    authenticated_content.sign(@cipher_suite, signature_private_key, group_context)
    membership_key = Melos::KeySchedule.membership_key(@cipher_suite, @epoch_secret)
    public_message = Melos::Struct::PublicMessage.protect(authenticated_content, @cipher_suite, membership_key, group_context)
    public_message
  end

  # message is the raw message,
  # key_package is a Melos::Struct::MLSMessage that has a KeyPackage type
  def join_with_welcome(message, key_package)
    message_obj = Melos::Struct::MLSMessage.new(message)
    if message_obj.welcome.nil?
      raise ArgumentError.new('Wrong message type (need a Welcome message)')
    end
    welcome = message_obj.welcome
    kp_ref = key_package.key_package.ref(suite)
    encrypted_group_secrets = welcome.secrets.find { _1.new_member == kp_ref }&.encrypted_group_secrets
    group_secrets = Melos::Struct::GroupSecrets.new(
      Melos::Crypto.decrypt_with_label(
      suite,
      init_priv,
      "Welcome",
      welcome.welcome.encrypted_group_info,
      egs.kem_output,
      egs.ciphertext
      )
    )
  end
end