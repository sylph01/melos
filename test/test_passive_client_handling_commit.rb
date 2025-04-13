require 'json'
require 'melos'
require 'minitest'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

vectors = JSON.load_file('test_vectors/passive-client-handling-commit.json')[0..6]

vectors.each_with_index do |vec, vec_index|
  puts "vector # #{vec_index}:"
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

  key, nonce = Melos::KeySchedule.welcome_key_and_nonce(suite, joiner_secret, psk_secret)
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
    ratchet_tree = Melos::Struct::RatchetTree.parse(from_hex(vec['ratchet_tree']))
  else
    # get ratchet tree from extensions
    ratchet_tree = Melos::Struct::RatchetTree.parse(group_info.extensions.find { _1.extension_type == Melos::Constants::ExtensionType::RATCHET_TREE }.extension_data)
  end
  # get signer key
  pub_key_of_signer = ratchet_tree[group_info_signer * 2].leaf_node.signature_key
  assert group_info.verify(suite, pub_key_of_signer)

  group_context = group_info.group_context
  # we want this out of processing welcome

  epoch_secret = Melos::KeySchedule.epoch_secret(suite, joiner_secret, psk_secret, group_context)
  epoch_authenticator = Melos::KeySchedule.epoch_authenticator(suite, epoch_secret)
  assert_equal epoch_authenticator, from_hex(vec['initial_epoch_authenticator'])
  puts "[pass] Verify that the locally computed epoch_authenticator value is equal to the initial_epoch_authenticator value"

  ## these values are group state
  # need to find which leaf the current user is
  node_index_of_current_user = ratchet_tree.find_index { _1&.leaf_node&.encryption_key == encryption_pub_from_key_package }
  leaf_index_of_current_user = node_index_of_current_user / 2
  encryption_priv_tree = []
  encryption_priv_tree[node_index_of_current_user] = encryption_priv

  interim_transcript_hash = Melos::Crypto.hash(suite, group_context.confirmed_transcript_hash + Melos::Vec.from_string(group_info.confirmation_tag))
  resumption_psks = []
  resumption_psks[group_context.epoch] = Melos::KeySchedule.resumption_psk(suite, epoch_secret)
  # advance init secret
  init_secret = Melos::KeySchedule.init_secret(suite, epoch_secret)
  ## end of group state values

  # process the following epochs
  vec['epochs'].each do |epoch_info|
    commit_msg = Melos::Struct::MLSMessage.new(from_hex(epoch_info['commit']))
    if commit_msg.public_message
      # convert list of proposals into a map of (proposalref) -> (authenticatedcontent)
      proposal_map = epoch_info['proposals']
        .map { Melos::Struct::MLSMessage.new(from_hex(_1)) }
        .map { _1.public_message.unprotect(suite, Melos::KeySchedule.membership_key(suite, epoch_secret), group_context) }
        .map { [Melos::Crypto.make_proposal_ref(suite, _1.raw), _1] }.to_h

      # verify epoch number
      assert_equal group_context.epoch, commit_msg.public_message.content.epoch
      # unprotect the commit
      authenticated_content = commit_msg.public_message.unprotect(suite, Melos::KeySchedule.membership_key(suite, epoch_secret), group_context)
      assert !authenticated_content.nil? # assert that it actually unprotects

      # based on sender, find public key
      if commit_msg.public_message.content.sender.sender_type == Melos::Constants::SenderType::MEMBER
        sender_leaf_index = commit_msg.public_message.content.sender.leaf_index
        sender_node_index = commit_msg.public_message.content.sender.leaf_index * 2
      end
      public_key = ratchet_tree[sender_node_index].leaf_node.signature_key
      assert authenticated_content.verify(suite, public_key, group_context)

      commit = commit_msg.public_message.content.commit
      # p commit

      # convert references into actual list of proposals
      proposal_list = commit.proposals.map do |prop_or_ref|
        if prop_or_ref.proposal
          prop_or_ref.proposal
        else
          proposal_map[prop_or_ref.reference].content.proposal
        end
      end

      # validate proposal list
      # p commit.proposals
      # puts "proposal types:"
      # commit.proposals.each { puts _1.proposal&.proposal_type }
      # apply proposal list
      # TODO: define RatchetTree.apply_proposal() or Group.apply_proposal()
      # in this order
      # GroupContextExtensions
      group_context_extensions = proposal_list.select { _1.proposal_type == Melos::Constants::ProposalType::GROUP_CONTEXT_EXTENSIONS }

      # Update
      updates = proposal_list.select { _1.proposal_type == Melos::Constants::ProposalType::UPDATE }
      updates.each do |prop|
        node = Melos::Struct::Node.new_leaf_node(prop.update.leaf_node)
        Melos::Struct::RatchetTree.update_leaf_node(ratchet_tree, node, sender_leaf_index)
      end

      # Remove
      removes = proposal_list.select { _1.proposal_type == Melos::Constants::ProposalType::REMOVE }
      removes.each do |prop|
        removed = prop.remove.removed
        Melos::Struct::RatchetTree.remove_leaf_node(ratchet_tree, removed)
      end
      # Add
      adds = proposal_list.select { _1.proposal_type == Melos::Constants::ProposalType::ADD }
      joiners = []
      adds.each do |prop|
        node = Melos::Struct::Node.new_leaf_node(prop.add.key_package.leaf_node)
        inserted_leaf_index = Melos::Struct::RatchetTree.add_leaf_node(ratchet_tree, node)
        joiners << inserted_leaf_index
      end
      p joiners if joiners.count > 0

      # PreSharedKey
      psks = proposal_list.select { _1.proposal_type == Melos::Constants::ProposalType::PSK }.map { _1.psk.psk }
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

      # Verify that the path value is populated if the proposals vector contains any Update or Remove proposals, or if it's empty. Otherwise, the path value MAY be omitted.

      # If the path value is populated, validate it and apply it to the tree:
      # validations TODO
      # p commit
      if commit.path
        Melos::Struct::RatchetTree.merge_update_path(suite, ratchet_tree, sender_leaf_index, commit.path)
      end

      group_context = Melos::Struct::GroupContext.create(
        cipher_suite: group_context.cipher_suite,
        group_id: group_context.group_id,
        epoch: group_context.epoch + 1,
        tree_hash: Melos::Struct::RatchetTree.root_tree_hash(suite, ratchet_tree),
        confirmed_transcript_hash: group_context.confirmed_transcript_hash, # provisional
        extensions: group_context.extensions # assume no GroupContextExtensions proposal
      )

      if commit.path
        # decrypt the path secrets for UpdatePath
        # assumes that this client is leaf 0
        decrypted_path_secret = Melos::Struct::RatchetTree.decrypt_path_secret(suite, ratchet_tree, encryption_priv_tree, commit.path, sender_leaf_index, leaf_index_of_current_user, group_context, joiners)
        commit_secret = Melos::Struct::RatchetTree.calculate_commit_secret(suite, ratchet_tree, commit.path, sender_leaf_index, leaf_index_of_current_user, decrypted_path_secret)
      else
        commit_secret = Melos::Crypto::Util.zero_vector(suite.kdf.n_h)
      end

      # calculate transcript hash and next interim transcript hash
      confirmed_transcript_hash = Melos::Crypto.hash(suite, interim_transcript_hash + authenticated_content.confirmed_transcript_hash_input.raw)
      interim_transcript_hash = Melos::Crypto.hash(suite, confirmed_transcript_hash + Melos::Vec.from_string(authenticated_content.auth.confirmation_tag))

      # new group context
      group_context = Melos::Struct::GroupContext.create(
        cipher_suite: group_context.cipher_suite,
        group_id: group_context.group_id,
        epoch: group_context.epoch,
        tree_hash: group_context.tree_hash,
        confirmed_transcript_hash: confirmed_transcript_hash,
        extensions: group_context.extensions
      )

      # derive the PSK secret
      # assume empty
      psk_secret = Melos::PSK.psk_secret(suite, psks)

      # calculate joiner, welcome, epoch secret
      joiner_secret = Melos::KeySchedule.joiner_secret(suite, init_secret, commit_secret, group_context)
      # welcome_secret = Melos::KeySchedule.welcome_secret(suite, joiner_secret, psk_secret)
      epoch_secret = Melos::KeySchedule.epoch_secret(suite, joiner_secret, psk_secret, group_context)
      epoch_authenticator = Melos::KeySchedule.epoch_authenticator(suite, epoch_secret)
      assert_equal epoch_authenticator, from_hex(epoch_info['epoch_authenticator'])
      puts "[pass] Verify that the locally computed epoch_authenticator value is equal to the epoch_authenticator value for epoch #{group_context.epoch}"

      # then update init secret
      init_secret = Melos::KeySchedule.init_secret(suite, epoch_secret)
    else
      # is a private message
    end
  end
end
