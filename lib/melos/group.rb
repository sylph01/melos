class Melos::Group
  attr_accessor :epoch, :cipher_suite, :group_id, :confirmed_transcript_hash, :interim_transcript_hash, :extensions,
    :self_leaf_index, :secrets, :ratchet_tree, :encryption_priv_tree,

  def context
    Melos::Struct::GroupContext.create(
      cipher_suite: @cipher_suite,
      group_id: @group_id,
      epoch: @epoch,
      tree_hash: Melos::Struct::RatchetTree.root_tree_hash(suite, ratchet_tree),
      confirmed_transcript_hash: @confirmed_transcript_hash,
      extensions: @extensions
    )
  end
end
