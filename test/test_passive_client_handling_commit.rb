require 'json'
require 'melos'
require 'minitest'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

vectors = JSON.load_file('test_vectors/passive-client-handling-commit.json')[0..12]

vectors.each_with_index do |vec, vec_index|
  puts "vector # #{vec_index}, cipher suite #{vec['cipher_suite']}:"
  suite = Melos::Crypto::CipherSuite.new(vec['cipher_suite'])
  # As reading from bc-java's implementation, this test assumes that psk_nonce is the psk itself...?
  external_psks = vec['external_psks'].map {
    [from_hex(_1['psk_id']), from_hex(_1['psk'])]
  }.to_h
  # it says /* serialized KeyPackage */ but it's actually an MLSMessage that has a KeyPackage inside it!
  key_package = Melos::Struct::MLSMessage.new(from_hex(vec['key_package']))
  signature_priv = from_hex(vec['signature_priv'])
  encryption_priv = from_hex(vec['encryption_priv']) # hello what is a `leaf_priv`?
  init_priv = from_hex(vec['init_priv'])

  # Verify that signature_priv, leaf_priv, and init_priv correspond to the public keys (signature_key, encryption_key, and init_key) in the KeyPackage object described by key_package
  init_pub_from_keypackage = key_package.key_package.init_key
  signature_pub_from_keypackage = key_package.key_package.leaf_node.signature_key
  encryption_pub_from_key_package = key_package.key_package.leaf_node.encryption_key

  assert Melos::Crypto.signature_key_pair_corresponds?(suite, signature_priv, signature_pub_from_keypackage)
  assert Melos::Crypto.encapsulation_key_pair_corresponds?(suite, init_priv, init_pub_from_keypackage)
  assert Melos::Crypto.encapsulation_key_pair_corresponds?(suite, encryption_priv, encryption_pub_from_key_package)
  puts "[pass] Verify that signature_priv, leaf_priv, and init_priv correspond to the public keys (signature_key, encryption_key, and init_key) in the KeyPackage object described by key_package"

  welcome = Melos::Struct::MLSMessage.new(from_hex(vec['welcome']))

  # 12.4.3.1 Joining via Welcome Message
  # Join the group using the Welcome message described by welcome, the ratchet tree described by ratchet_tree (if given) and the pre-shared keys described in external_psks
  # param: welcome message itself, keypackage, external_psks(psk_id_name -> psk)
  kp_ref = key_package.key_package.ref(suite)
  # identify which new_member entry to use
  egs = welcome.welcome.secrets.find { _1.new_member == kp_ref }&.encrypted_group_secrets

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
  joiner_secret = group_secrets.joiner_secret
  psk_ids = group_secrets.psks
  psks = psk_ids.map do |psk_id|
    [psk_id.raw, external_psks[psk_id.psk_id]]
  end
  # TODO: If a PreSharedKeyID is part of the GroupSecrets and the client is not in possession of the corresponding PSK, return an error. Additionally, if a PreSharedKeyID has type resumption with usage reinit or branch, verify that it is the only such PSK.
  psk_secret = Melos::PSK.psk_secret(suite, psks)

  key, nonce = Melos::EpochSecrets.welcome_key_and_nonce(suite, joiner_secret, psk_secret)
  group_info = Melos::Struct::GroupInfo.new(
    Melos::Crypto.aead_decrypt(
      suite,
      key,
      nonce,
      "",
      welcome.welcome.encrypted_group_info
    )
  )

  ## verify signature of GroupInfo object
  group_info_signer = group_info.signer
  # construct ratchet tree
  if vec['ratchet_tree']
    # get ratchet tree from vector
    ratchet_tree = Melos::RatchetTree.parse(suite, from_hex(vec['ratchet_tree']))
  else
    # get ratchet tree from extensions
    ratchet_tree = Melos::RatchetTree.parse(suite, group_info.extensions.find { _1.extension_type == Melos::Constants::ExtensionType::RATCHET_TREE }.extension_data)
  end
  # get signer key
  pub_key_of_signer = ratchet_tree.leaf_node_at(group_info_signer).signature_key
  assert group_info.verify(suite, pub_key_of_signer)

  group_context = group_info.group_context
  # we want this out of processing welcome

  epoch = Melos::EpochSecrets.from_joiner(suite, joiner_secret, psk_secret, group_context, n_leaves: ratchet_tree.n_leaves)
  assert_equal epoch.epoch_authenticator, from_hex(vec['initial_epoch_authenticator'])
  puts "[pass] Verify that the locally computed epoch_authenticator value is equal to the initial_epoch_authenticator value"

  ## these values are group state
  # need to find which leaf the current user is
  leaf_index_of_current_user = ratchet_tree.find_leaf_index { _1.encryption_key == encryption_pub_from_key_package }
  private_tree = Melos::PrivateTree.new
  private_tree[leaf_index_of_current_user * 2] = encryption_priv

  interim_transcript_hash = Melos::Crypto.hash(suite, group_context.confirmed_transcript_hash + Melos::Vec.string_to_vec(group_info.confirmation_tag))
  resumption_psks = []
  resumption_psks[group_context.epoch] = epoch.resumption_psk
  ## end of group state values

  # process the following epochs
  vec['epochs'].each do |epoch_info|
    commit_msg = Melos::Struct::MLSMessage.new(from_hex(epoch_info['commit']))
    # p commit_msg
    # p leaf_index_of_current_user
    if commit_msg.public_message
      # convert list of proposals into a map of (proposalref) -> (authenticatedcontent)
      proposal_map = epoch_info['proposals']
        .map { Melos::Struct::MLSMessage.new(from_hex(_1)) }
        .map { _1.public_message.unprotect(suite, epoch.membership_key, group_context) }
        .map { [Melos::Crypto.make_proposal_ref(suite, _1.raw), _1] }.to_h

      # verify epoch number
      assert_equal group_context.epoch, commit_msg.public_message.content.epoch
      # unprotect the commit
      authenticated_content = commit_msg.public_message.unprotect(suite, epoch.membership_key, group_context)
      assert !authenticated_content.nil? # assert that it actually unprotects

      # based on sender, find public key
      if commit_msg.public_message.content.sender.sender_type == Melos::Constants::SenderType::MEMBER
        sender_leaf_index = commit_msg.public_message.content.sender.leaf_index
      end
      public_key = ratchet_tree.leaf_node_at(sender_leaf_index).signature_key
      assert authenticated_content.verify(suite, public_key, group_context)

      commit = commit_msg.public_message.content.commit

      # convert references into actual list of [proposal, sender]s
      proposal_list = commit.proposals.map do |prop_or_ref|
        if prop_or_ref.proposal
          [prop_or_ref.proposal, sender_leaf_index]
        else
          [proposal_map[prop_or_ref.reference].content.proposal, proposal_map[prop_or_ref.reference].content.sender.leaf_index] # TODO: resolve leaf index
        end
      end
      print "Proposal types: "
      p proposal_list.map { Melos::Constants::ProposalType::NAMES[_1[0].proposal_type] }

      # puts "Tree before apply:"
      # ratchet_tree.dump

      # validate proposal list
      # p commit.proposals
      # puts "proposal types:"
      # commit.proposals.each { puts _1.proposal&.proposal_type }
      # apply proposal list
      # TODO: define RatchetTree.apply_proposal() or Group.apply_proposal()
      # in this order
      # GroupContextExtensions
      group_context_extensions = proposal_list.select { _1[0].proposal_type == Melos::Constants::ProposalType::GROUP_CONTEXT_EXTENSIONS }
      group_context_extensions.each do |prop_tuple|
        proposal = prop_tuple[0]
        group_context.extensions = proposal.group_context_extensions.extensions
      end

      # Update
      updates = proposal_list.select { _1[0].proposal_type == Melos::Constants::ProposalType::UPDATE }
      updates.each do |prop|
        proposal = prop[0]
        ratchet_tree.update_leaf_node(prop[1], proposal.update.leaf_node)
      end

      # Remove
      removes = proposal_list.select { _1[0].proposal_type == Melos::Constants::ProposalType::REMOVE }
      removes.each do |prop|
        proposal = prop[0]
        removed = proposal.remove.removed
        ratchet_tree.remove_leaf_node(removed)
      end
      # Add
      adds = proposal_list.select { _1[0].proposal_type == Melos::Constants::ProposalType::ADD }
      joiners = []
      adds.each do |prop|
        proposal = prop[0]
        inserted_leaf_index = ratchet_tree.add_leaf_node(proposal.add.key_package.leaf_node)
        joiners << inserted_leaf_index
      end

      # PreSharedKey
      psks = proposal_list.select { _1[0].proposal_type == Melos::Constants::ProposalType::PSK }.map { _1[0].psk.psk }
      psks = psks.map {
        if _1.psktype == Melos::Constants::PSKType::EXTERNAL
          [_1.raw, external_psks[_1.psk_id]]
        else
          # resumption
          # Group remembers some numbers of Resumption PSKs tied to an Epoch (generated from epoch secret), and it will be referenced here
          [_1.raw, resumption_psks[_1.psk_epoch]]
        end
      }

      # ExternalInit

      # ReInit

      # puts "Tree after apply:"
      # ratchet_tree.dump

      group_context = Melos::Struct::GroupContext.create(
        cipher_suite: group_context.cipher_suite,
        group_id: group_context.group_id,
        epoch: group_context.epoch,
        tree_hash: ratchet_tree.root_tree_hash,
        confirmed_transcript_hash: group_context.confirmed_transcript_hash, # provisional
        extensions: group_context.extensions # assume no GroupContextExtensions proposal
      )

      # Verify that the path value is populated if the proposals vector contains any Update or Remove proposals, or if it's empty. Otherwise, the path value MAY be omitted.

      # If the path value is populated, validate it and apply it to the tree:
      # validations TODO
      # p commit
      if commit.path
        ratchet_tree.merge_update_path(sender_leaf_index, commit.path)

        provisional_group_context = Melos::Struct::GroupContext.create(
          cipher_suite: group_context.cipher_suite,
          group_id: group_context.group_id,
          epoch: group_context.epoch + 1,
          tree_hash: ratchet_tree.root_tree_hash,
          confirmed_transcript_hash: group_context.confirmed_transcript_hash, # provisional
          extensions: group_context.extensions # assume no GroupContextExtensions proposal
        )
        # ratchet_tree.dump
        # puts "root hash: " + to_hex(ratchet_tree.root_tree_hash)

        # decrypt the path secrets for UpdatePath
        # assumes that this client is leaf 0
        decrypted_path_secret = ratchet_tree.decrypt_path_secret(private_tree, commit.path, sender_leaf_index, leaf_index_of_current_user, provisional_group_context, joiners)
        commit_secret = ratchet_tree.calculate_commit_secret(commit.path, sender_leaf_index, leaf_index_of_current_user, decrypted_path_secret)
      else
        commit_secret = Melos::Crypto::Util.zero_vector(suite.kdf.n_h)
      end

      # calculate transcript hash and next interim transcript hash
      confirmed_transcript_hash = Melos::Crypto.hash(suite, interim_transcript_hash + authenticated_content.confirmed_transcript_hash_input.raw)
      interim_transcript_hash = Melos::Crypto.hash(suite, confirmed_transcript_hash + Melos::Vec.string_to_vec(authenticated_content.auth.confirmation_tag))

      # new group context
      group_context = Melos::Struct::GroupContext.create(
        cipher_suite: group_context.cipher_suite,
        group_id: group_context.group_id,
        epoch: group_context.epoch + 1,
        tree_hash: ratchet_tree.root_tree_hash,
        confirmed_transcript_hash: confirmed_transcript_hash,
        extensions: group_context.extensions
      )

      # derive the PSK secret
      psk_secret = Melos::PSK.psk_secret(suite, psks)

      # advance the key schedule to the new epoch
      epoch = epoch.next(commit_secret, psk_secret, group_context, n_leaves: ratchet_tree.n_leaves)
      assert_equal epoch.epoch_authenticator, from_hex(epoch_info['epoch_authenticator'])
      puts "[pass] Verify that the locally computed epoch_authenticator value is equal to the epoch_authenticator value for epoch #{group_context.epoch}"
      resumption_psks[group_context.epoch] = epoch.resumption_psk
    else
      # is a private message
    end
  end
end
