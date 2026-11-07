# Roadmap: the missing features, smallest first

What melos does not implement yet, as of 0.1.0, ordered by implementation effort. Each item says
what the RFC asks for, what the code already has, what to build, and how to test it. Effort is
S (hours), M (a day or two), L (a week or more). Items are independent unless noted.

The list comes from the "not yet" section of the README, the deferred rows of
[validation.md](validation.md), and the `TODO` comments in `lib/`.

## 1. Exporters (S) — RFC 8.5 — done in 7c57cac

**RFC.** `MLS-Exporter(Label, Context, Length) = ExpandWithLabel(DeriveSecret(exporter_secret, Label), "exported", Hash(Context), Length)`.

**Have.** `EpochSecrets#exporter_secret`, `Crypto.expand_with_label`, `Crypto.derive_secret`.

**Build.** `EpochSecrets#export(label, context, length)` and `Group#export_secret(label, context, length)`
delegating to the current epoch. Also expose `Group#epoch_authenticator` (exists) and the
`resumption_psk` of past epochs is already kept.

**Test.** There is no exporter vector in mls-implementations; test determinism between two members in
the round-trip test, and against a hand computation in `test_key_schedule.rb`.

## 2. An error class hierarchy (S) — done in 43a039d

**Have.** Every rejection raises `ArgumentError` with a message. Callers cannot tell a malformed
message from a wrong argument, or a commit that removed them from a tampered one.

**Build.** `Melos::Error < StandardError`, with `Melos::ProtocolError` (malformed or invalid input: the
validation failures), `Melos::StateError` (wrong group state: inactive group, pending proposals,
unknown epoch) and `Melos::UnsupportedError` (features below). Replace the `raise ArgumentError` sites
in `group.rb`, `group/validation.rb`, `ratchet_tree.rb`, `secret_tree.rb`, `vec.rb` and `structs.rb`.
Keep `ArgumentError` for genuine caller mistakes. `test_validation.rb` then asserts the specific class.

Do this before 3 to 12, since all of them add error sites.

## 3. Partial commits: omit the UpdatePath when allowed (S) — RFC 12.4 — done in e9a27c9

**RFC.** The path MAY be omitted when the commit covers at least one proposal and none of them is of a
path-required type (Update, Remove, ExternalInit, GroupContextExtensions). The commit secret is then
all zeros.

**Have.** `Group#stage` already handles `commit.path == nil` (zero commit secret, no decryption) and
enforces the path-required rule. `create_commit` always builds a path (`TODO` at group.rb:351).

**Build.** A `path:` option on `create_commit`: `:always` (default, keeps PCS for the committer),
`:if_required`. When omitted, no `create_update_path`, no private tree change, no `path_secret` in the
Welcome (`GroupSecrets.path_secret` nil, which `from_welcome` already accepts).

**Test.** Round trip: Alice adds Bob with `path: :if_required`; Bob joins without a path secret and
can decrypt Alice's next commit; a Remove with `path: :if_required` still produces a path.

## 4. Update proposals (S/M) — RFC 12.1.2, 7.3 — done

**RFC.** A member replaces its own leaf with a fresh encryption key (`leaf_node_source = update`,
signed with group id and leaf index). When a commit applies the Update, the member's leaf private
key becomes the new one. The committer must not commit its own Update.

**Have.** Receiving side is complete: `apply_proposals` validates the leaf (context `:update`) and
replaces it. `KeyPackageBundle.generate` shows how a signed leaf is built.

**Build.** `Group#create_update_proposal(capabilities: nil, extensions: nil)`: new encryption key pair,
`LeafNode.create(leaf_node_source: UPDATE, ...)` from the current leaf, `sign(suite, key, group_id,
leaf_index)`, send via `create_proposal`. Remember the private key in a `@pending_updates` map keyed
by the new encryption key. In `merge_commit`, if our leaf now carries one of those keys, set
`private_tree[leaf_index * 2]` to it and drop the rest. `create_commit` already refuses our own
Update in the list (12.2), so a member with a pending Update must wait for someone else's commit, or
commit without it (its path replaces the leaf anyway).

**Test.** Bob proposes an Update, Alice commits it, both agree; Bob's private tree is consistent
and he can still decrypt the next commit. Two pending Updates from Bob: the committer applies one.

## 5. Deletion schedule (M) — RFC 9.2, 7.5 — done

**RFC.** Consumed secrets MUST be deleted immediately: `commit_secret`, `joiner_secret`,
`epoch_secret`, `encryption_secret` of the epoch and `init_secret` of the previous one, the secret
tree node secrets on the path to a used leaf, used ratchet secrets, and the path and node secrets
used to derive updated nodes. Unconsumed values MAY be kept for a bounded time.

**Have.** `merge_commit` drops the previous `EpochSecrets` and the staged commit. `SecretTree::Ratchet`
forgets each ratchet secret as it steps. But `EpochSecrets` memoizes every derived secret for the
epoch's life, keeps `joiner_secret` and `psk_secret`, and `PrivateTree` keeps private keys for nodes
that no longer exist or were replaced (the stale-key case the treekem test notes).

**Build.** `EpochSecrets#consume!` dropping `epoch_secret`, `joiner_secret`, `init_secret` and
`encryption_secret` once the secret tree exists and the Welcome is built; `PrivateTree#prune!(tree)`
removing keys whose node is blank or has a different public key, called from `merge_commit`;
`StagedCommit` cleared of `path_secrets` once the Welcome exists. Ruby strings cannot be reliably
zeroized, so this is about not retaining references; say so in the docs.

**Test.** After a commit, the previous epoch's secrets are gone from the group; `private_tree`
holds exactly the keys for nodes on our direct path that exist.

## 6. Out-of-order and old-epoch application messages (M) — RFC 9.1, 15.3, 12.4.2 — done

**RFC.** Receivers keep unused generation keys of a sender's ratchet for a while, and the secret
trees of recent epochs, so delayed and reordered messages decrypt. Applications SHOULD bound how
far a ratchet may be advanced by one message and how many unused keys are kept.

**Have.** `SecretTree::Ratchet#ratchet_until` refuses any generation older than the last derived
(`TODO` at secret_tree.rb:32); `Group#unprotect` rejects any epoch but the current one
(`TODO` at group.rb:219).

**Build.** In `Ratchet`, a `Hash` of unconsumed `generation => [key, nonce]` with a maximum size and a
maximum forward jump, both options; `ratchet_until` serves from it and deletes on use. In `Group`,
keep `EpochSecrets` of the last N epochs (option, default a small number) in `@past_epochs`, and let
`unprotect` select by `PrivateMessage.epoch` for application messages only. Handshake messages stay
current-epoch only. Interacts with 5: a retained epoch's secrets are not yet "consumed".

**Test.** Deliver two application messages in reverse order; deliver an application message from the
previous epoch after a commit; a generation jump beyond the bound is rejected.

**Done as.** `SecretTree::Ratchet` keeps skipped `generation => [key, nonce]`, bounded by
`out_of_order_tolerance:` (default 100, oldest dropped) and `max_forward_distance:` (default 1000,
`ProtocolError` beyond). `Group` keeps `PastEpoch` (secret tree and sender data secret only, plus the
GroupContext and tree for the signature check) for `max_past_epochs:` epochs (default 2). The
options go to `Group.create` / `.from_welcome` (and so `Client#create_group` / `#join_group`).
AEAD failures now raise `ProtocolError`.

## 7. External senders and external proposals (M) — RFC 12.1.8, 12.1.8.1, 6.1 — done

**RFC.** With an `external_senders` GroupContext extension, listed signers may send Add, Remove,
PreSharedKey, ReInit and GroupContextExtensions proposals as PublicMessages with
`sender_type = external` and `sender_index` into the extension. A joiner may also send its own Add as
`new_member_proposal`, signed with the KeyPackage's key. Other proposal types from these senders
MUST be rejected.

**Have.** `Struct::ExternalSender` and `Struct::Sender.create_external` parse and build. `Group#unprotect`
rejects non-member senders (`TODO` at group.rb:488), `resolve_proposals` rejects proposals by
reference from non-members.

**Build.** Decode the extension in `Group` (like `required_capabilities`); `sender_signature_key` for
`external` (by index) and `new_member_proposal` (the KeyPackage inside the Add); the content-type
and proposal-type restrictions of 6.1 and 12.1.8; PublicMessage only; `resolve_proposals` passes
`nil` as the sender leaf of such proposals, and `apply_proposals` must not treat an external Remove
as touching the sender. An `ExternalSender` API for the sending side (sign a proposal with no
group membership) is a small separate class.

**Test.** An external signer removes Bob; a non-member sends its own Add; an external Update is
rejected.

**Done as.** `Struct::ExternalSenders` (the extension data, with `.extension(list)`), `Group#external_senders`,
`#validate_non_member_content!` and `#sender_signature_key` for `external` and `new_member_proposal`;
`resolve_proposals` gives such proposals a `nil` sender. `Melos::ExternalSender` signs proposals with
no group state (`create_add_proposal`, `create_remove_proposal`, `create_psk_proposal`,
`create_group_context_extensions_proposal`); `Client#create_new_member_proposal` sends a client's own
Add. Authorization (12.1.8) is the `external_proposal_validator:` group option, accepting by default.
Tests in `test/test_external_senders.rb`.

## 8. Persistence of client and group state (M)

**RFC.** None, but 6.3.1 requires persistent ratchet state to avoid nonce reuse, so a client that
restarts without it is unsafe.

**Have.** All state lives in instance variables of `Client`, `Group`, `EpochSecrets`, `SecretTree`,
`PrivateTree`, `RatchetTree`; the public tree already round-trips through `raw`.

**Build.** `Group#to_h` / `Group.from_h` (and the same for `Client`) producing plain Hashes of binary
strings and integers, including the secret tree ratchet positions, pending proposals (as
`AuthenticatedContent.raw`), pending updates (4) and retained epochs (6). Serialization format is the
application's choice (Marshal, JSON with hex, MessagePack); provide the Hash and one JSON helper.
Encryption at rest is out of scope and should be stated.

**Test.** Save and restore both members between every step of the round-trip test; messages
encrypted before and after a restore decrypt.

## 9. X.509 credentials (M, application-dependent) — RFC 5.3, 5.3.1, 13.3

**RFC.** The AS validates credentials; for X.509 the end-entity certificate's public key MUST equal the
leaf's `signature_key`, and the chain is verified by the application's policy.

**Have.** `Struct::Credential` parses `certificates`; the default `credential_validator` accepts basic
credentials only.

**Build.** `Melos::Credential::X509` helper: parse `cert_data` with `OpenSSL::X509::Certificate`, check
the key matches `signature_key`, verify the chain against a caller-supplied store, check validity
dates; offered as an alternative validator the application opts into. Capabilities default gains
credential type 2 only when the validator is installed.

**Test.** A self-signed chain generated in the test; a certificate whose key differs from the leaf's
is rejected.

## 10. Resumption PSKs, ReInit and subgroup branching (M/L) — RFC 8.4, 11.2, 11.3, 12.1.5, 12.4.3.1

**RFC.** ReInit: a proposal (alone in its commit) ends the group; the committer creates a new group
with the proposed version, suite, id and extensions, and welcomes everyone with a resumption PSK of
usage `reinit` for the old group's last epoch; joiners verify the new group's parameters against the
proposal and that membership is preserved. Branching: a member creates a subgroup of existing
members with a resumption PSK of usage `branch`; joiners verify suite, version, epoch 1 and that
every leaf matches one in the old group. Resumption PSKs of these usages are invalid anywhere else.

**Have.** `Struct::ReInit` parses; `resumption_psks` by epoch are kept; `psk_secret_for` handles
resumption PSKs by epoch but ignores `usage` and `psk_group_id` (`TODO` at group.rb:560);
`from_welcome` rejects resumption PSKs in a Welcome (`TODO` at group.rb:134); `apply_proposals`
rejects ReInit as unsupported.

**Build.** `Client` keeps the resumption PSKs of groups it left or that were reinitialized, keyed by
group id and epoch. `Group#create_reinit_proposal`, ReInit handling in `stage`/`merge_commit` (the
group becomes inactive with a `pending_reinit`), `Client#create_reinit_group(old_group)` which creates
the new group and the Welcome with the PSK, `Client#create_branch(old_group, members)`, and the
joiner-side checks of 11.2, 11.3 and 12.4.3.1 in `from_welcome`. Needs 3 (the branch commit has
only Adds and a PSK) and benefits from 2.

**Test.** Reinit a three-member group to another cipher suite; branch Alice and Carol out of
Alice, Bob and Carol; a `reinit` PSK in an ordinary commit is rejected.

## 11. External commits (L) — RFC 12.4.3.2, 8.3, 12.1.6

**RFC.** A member publishes a GroupInfo with an `external_pub` extension; a joiner builds a commit
with `sender_type = new_member_commit`, an ExternalInit proposal carrying the HPKE `kem_output`,
optionally a Remove of its old self, and a path from the leaf it takes; members derive the next
`init_secret` from the external secret, assign the joiner the leftmost blank leaf, and verify the
signature with the path leaf's key.

**Have.** `Struct::ExternalInit`, `Struct::ExternalPub`, `Struct::GroupInfo` parse and build;
`EpochSecrets#external_secret` is derived; `stage` rejects non-member committers and ExternalInit
(`TODO` at group.rb:409).

**Build.** `Group#group_info(external_pub: true)` deriving the external key pair from
`external_secret` (8.3); `Client#join_by_external_commit(group_info, ratchet_tree:)` producing the
commit and a new `Group`; in `stage`, the `new_member_commit` branch: leaf assignment, the external
init secret via `EpochSecrets#next` with an `init_secret:` override, the 12.2 external list rules,
signature from the path leaf. `validate_update_path!` must allow the joiner's leaf to be new.
Needs 2 and 3; shares the leaf-assignment code with Add.

**Test.** Carol joins Alice and Bob by external commit; a resync commit replaces an old Carol; an
external commit with a proposal by reference is rejected.

## 12. Interop testing (L)

**RFC.** None; the mls-implementations repository defines a gRPC interop harness
(`mls_client.proto`) that drives each implementation through a test runner.

**Have.** All test vectors pass, and the round-trip tests only pit melos against itself.

**Build.** A `melos-interop` executable implementing the gRPC `MLSClient` service with `grpc` and
`google-protobuf` gems (development dependencies only): state handles for groups, the
create/join/propose/commit/protect/unprotect operations mapped to `Client` and `Group`. Run the
upstream test runner against melos and at least one other implementation (OpenMLS has a ready
interop client). Expect this to surface issues that vectors cannot, particularly around 3, 6 and
7. Depends on nothing but gets more valuable after each item above lands; 7 and 11 are exercised by
the runner's scripts.

**Test.** The runner's own scripts; keep a record of which pass in this file.

## Suggested sequence

~~2 → 1 → 3 → 4 → 5 → 6 → 7~~ → 8 → 10 → 11 → 9 → 12, with interop (12) ready to start,
since it is the strongest check on everything else and takes calendar time rather than code.
