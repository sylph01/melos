# RFC 9420 validation checklist

MUST-level requirements of RFC 9420 that apply to a client processing or producing messages,
mapped to the code; updated as validation lands (last: tier 5). Status:

- **done**: enforced today, with where.
- **partial**: enforced in some paths or weaker than the RFC asks.
- **missing**: not enforced.
- **n/a**: for features melos does not implement yet (external commits); the code rejects these inputs with a clear error instead.

Items marked *(application)* are MUSTs the RFC places on the application or the Authentication
Service; melos should offer a hook or a documented default, not decide the policy.

## 1. Message framing and unprotect (Sections 6, 6.1, 6.2, 6.3)

| # | Requirement | RFC | Status | Code |
|---|---|---|---|---|
| 1.1 | Verify the signature with the key selected by sender_type | 6.1 | partial | `Group#unprotect`, `#sender_signature_key`: member (leaf), external (external_senders entry), new_member_proposal (the Add's KeyPackage leaf); new_member_commit raises "not supported" |
| 1.2 | external sender: content_type MUST be proposal, proposal_type MUST be one allowed for external senders | 6.1, 12.1.8 | done | `#validate_non_member_content!` with `EXTERNAL_PROPOSAL_TYPES` |
| 1.3 | new_member_commit: content_type MUST be commit; new_member_proposal: proposal of type add | 6.1 | done | `#validate_non_member_content!` |
| 1.4 | PublicMessage: check membership_tag for member senders | 6.2 | done | `PublicMessage#unprotect` returns nil, `Group#unprotect` raises |
| 1.5 | FramedContentAuthData valid: signature and, for commits, confirmation_tag | 6.1, 6.2, 6.3.1 | done | signature in `Group#unprotect`; tag in `Group#stage` |
| 1.6 | PrivateMessage padding MUST be all zero bytes; reject otherwise | 6.3.1 | done | `PrivateMessage#unprotect` via `PrivateMessageContent#padding_zero?` |
| 1.7 | SenderData.leaf_index MUST identify a non-blank leaf | 6.3.2 | partial | caught later by `#sender_signature_key` ("sender leaf is blank") after decryption; the RFC wants it checked when the sender data is parsed |
| 1.8 | Application data MUST be sent as PrivateMessage | 6 | done | `AuthenticatedContent#sign` raises on send; `#verify` returns false on receive |
| 1.9 | Proposal and Commit epoch MUST equal the current epoch | 12.1, 12.4.2 | done | `Group#unprotect` |
| 1.10 | Application messages from earlier epochs and out of order may be decrypted, within application-chosen bounds (9.1, 15.3); handshake messages stay current-epoch only | 9.1, 15.3 | done | `Group#unprotect` selects a `PastEpoch` (`max_past_epochs:`) for application PrivateMessages; `SecretTree::Ratchet` keeps skipped keys (`out_of_order_tolerance:`) and refuses jumps over `max_forward_distance:` |
| 1.11 | MLSMessage.version MUST be mls10 | 6 | done | `Group.check_message_version!` in `#unprotect`, `.from_welcome`, `#create_add_proposal` |
| 1.12 | AAD plus ciphertext MUST fit the AEAD limits | 6.3.1, 15.2 | missing *(application)* | no size accounting anywhere |

## 2. Proposals as received (Section 12.1)

| # | Requirement | RFC | Status | Code |
|---|---|---|---|---|
| 2.1 | Verify signature and epoch before caching | 12.1 | done | `Group#unprotect`, `#process_proposal` |
| 2.2 | Add: KeyPackage valid per 10.1 (see section 4) | 12.1.1 | done | `#apply_proposals` -> `#validate_key_package!` |
| 2.3 | Update: LeafNode valid for an Update per 7.3, source `update`, encryption_key differs from the replaced leaf | 12.1.2, 7.3 | done | `#apply_proposals` -> `#validate_leaf_node!(context: :update)`; sent by `#create_update_proposal` |
| 2.4 | Remove: `removed` MUST be a non-blank leaf | 12.1.3 | done | `#apply_proposals` (both sides), `#create_remove_proposal` |
| 2.5 | PreSharedKey: psk_nonce length MUST be KDF.Nh | 12.1.4 | done | `#psk_secret_for` |
| 2.6 | PreSharedKey: resumption with usage reinit or branch is invalid outside those operations | 12.1.4, 11.2, 11.3 | done | `#psk_secret_for` accepts them only in the initial commit of a resumed group (`#create_resumption_commit`), which no other member processes |
| 2.7 | ReInit: version MUST NOT be lower than the current one | 12.1.5 | done | `#validate_proposal_list!` |
| 2.8 | GroupContextExtensions: invalid if required_capabilities not supported by all members after the commit | 12.1.7, 11.1 | done | `#validate_members!` after the list is applied |
| 2.9 | External proposals MUST be PublicMessage; only add, remove, psk, reinit, gce from external senders; external_senders extension must be present; unauthorized external proposals are invalid | 12.1.8 | done | `#validate_non_member_content!`, `#sender_signature_key`; authorization is the `external_proposal_validator:` hook *(application)*, accepting by default |
| 2.10 | Unknown (non-default) proposal types MUST be supported by every member that processes the commit | 12.2, 13.2 | done | `#apply_proposals` rejects any type outside `KNOWN_PROPOSAL_TYPES` |

## 3. Proposal list validation (Section 12.2), on both creating and processing a Commit

`Group#validate_proposal_list!` runs in both `#create_commit` and `#stage`.

| # | Requirement | RFC | Status |
|---|---|---|---|
| 3.1 | Every individual proposal valid (sections 2 and 4) | 12.2 | done (sections 2, 4, 5) |
| 3.2 | No Update proposal by the committer | 12.2 | done |
| 3.3 | No Remove of the committer | 12.2 | done (`#stage`, `#create_commit`) |
| 3.4 | No two Update/Remove proposals for the same leaf | 12.2 | done |
| 3.5 | No two Adds for the same client (e.g. same signature key) | 12.2 | done (same signature key) |
| 3.6 | No Add of a client already in the group unless a Remove in the same list removes it | 12.2 | done (same signature key) |
| 3.7 | No two PreSharedKey proposals with the same PreSharedKeyID | 12.2 | done |
| 3.8 | At most one GroupContextExtensions proposal | 12.2 | done |
| 3.9 | ReInit MUST be alone in the list | 12.2 | done (`#create_commit` also leaves a pending ReInit out when other proposals are at hand, as 12.2 suggests) |
| 3.10 | No ExternalInit in a regular commit | 12.2 | done by accident (`#apply_proposals` raises "unsupported") |
| 3.11 | After applying, every leaf in the tree is valid per 7.3 | 12.2 | done: capabilities and key uniqueness of every remaining leaf (`#validate_members!`); signatures were verified when each leaf entered |
| 3.12 | Reject the Commit if the list is invalid | 12.2 | follows from the above |
| 3.13 | External commit list rules (exactly one ExternalInit, at most one Remove, PSKs only) | 12.2 | n/a |

## 4. KeyPackage validation (Sections 10, 10.1), when adding and when processing an Add

| # | Requirement | RFC | Status | Code |
|---|---|---|---|---|
| 4.1 | cipher_suite and version match the GroupContext | 10.1 | done | `#apply_proposals` (Add) |
| 4.2 | leaf_node valid for a KeyPackage per 7.3 (section 5 below) | 10.1 | done | `#validate_key_package!` |
| 4.3 | Signature verifies with the leaf's signature key | 10, 10.1 | done | `#validate_key_package!` |
| 4.4 | leaf_node.encryption_key MUST differ from init_key | 10.1 | done | `#validate_key_package!` |
| 4.5 | leaf_node_source MUST be key_package | 10 | done | `#validate_leaf_node!(context: :key_package)` |
| 4.6 | Extensions in KeyPackage.extensions and leaf_node.extensions MUST be listed in leaf_node.capabilities | 10 | done | `#validate_key_package!`, `#validate_capabilities!` |
| 4.7 | KeyPackage.version MUST equal the enclosing MLSMessage.version | 10 | done | `Group#create_add_proposal` |
| 4.8 | Unknown capabilities values and unknown extensions MUST be ignored | 13.4 | done by construction | nothing inspects them yet; keep it that way when 4.6 is added |
| 4.9 | Sender: init_key MUST be unique among the client's KeyPackages | 10 | done | fresh random key per `KeyPackageBundle.generate` |
| 4.10 | Sender: capabilities MUST list every supported value and MUST NOT list default proposal/extension types | 7.2 | done | `Melos::Capabilities#set_default` lists no proposal or extension types |

## 5. LeafNode validation (Section 7.3), for Add, Update, the Commit path leaf, and every leaf when joining

| # | Requirement | RFC | Status | Code |
|---|---|---|---|---|
| 5.1 | Credential valid per 5.3.1 (Authentication Service) | 7.3, 5.3.1 | done (hook) | `credential_validator:` option; default accepts basic credentials only |
| 5.2 | Signature valid with signature_key (with group_id and leaf_index for update/commit sources) | 7.3 | done | `#validate_leaf_node!` |
| 5.3 | If GroupContext has required_capabilities, its extensions, proposals and credential types MUST be in the leaf's capabilities | 7.3, 11.1, 13.4 | done | `#validate_capabilities!` |
| 5.4 | Credential type supported by all members; leaf supports every credential type in use | 7.3, 13.3 | done | `#validate_leaf_node!`, `#validate_members!` |
| 5.5 | Lifetime: sender MUST check current time is within lifetime when sending a leaf (Add of a KeyPackage); receiver RECOMMENDED | 7.3 | done | `#validate_leaf_node!(sending: true)` from `#create_add_proposal` and `#create_commit` |
| 5.6 | Application MUST define a maximum total lifetime and reject longer ones | 7.2 | done (option) | `max_leaf_node_lifetime:`; no default limit because the interop vectors use the full uint64 range |
| 5.7 | Every non-default extension in the leaf MUST be listed in capabilities.extensions; credential type MUST be in capabilities.credentials | 7.2, 7.3 | done | `#validate_capabilities!` |
| 5.8 | leaf_node_source matches the context: key_package / update (and new encryption_key) / commit | 7.3 | done | `#validate_leaf_node!` |
| 5.9 | signature_key and encryption_key unique among members | 7.3, 16.7 | done | `#validate_leaf_node!`, `#validate_members!`, `#validate_tree!` |
| 5.10 | Each GroupContext extension (non-default) MUST be supported by a new member's capabilities | 13.4 | done | `#validate_capabilities!` |

## 6. Commit processing (Sections 12.4, 12.4.2, 7.5, 7.6, 7.9.2)

| # | Requirement | RFC | Status | Code |
|---|---|---|---|---|
| 6.1 | Epoch, membership tag or decryption, signature | 12.4.2 | done | `Group#unprotect` |
| 6.2 | Proposal list valid (section 3) | 12.4.2 | done | `#validate_proposal_list!` in `#stage` and `#create_commit` |
| 6.3 | All PreSharedKey proposals available | 12.4.2 | done | `#psk_secret_for` raises |
| 6.4 | Path MUST be present if the list is empty or has a path-required type | 12.4 | done | `Group#stage` |
| 6.5 | Path leaf valid per 7.3 with leaf_node_source commit | 12.4.2 | done | `#validate_update_path!` -> `#validate_leaf_node!(context: :commit)` |
| 6.6 | Path leaf encryption_key MUST differ from the committer's current leaf | 12.4.2 | done | `#validate_update_path!` |
| 6.7 | None of the UpdatePath public keys appear in any node of the new tree | 12.4.2 | done | `#validate_update_path!` |
| 6.8 | Recompute the committer's leaf parent_hash and verify it matches the supplied leaf | 7.9.2 | done | `#validate_update_path!` via `RatchetTree#verify_parent_hash_of_path` |
| 6.9 | Each UpdatePathNode's encrypted_path_secret length MUST equal the copath resolution excluding new leaves | 7.6 | done | `#validate_update_path!` checks every node |
| 6.10 | Confirmation tag verifies against the new epoch | 12.4.2 | done | `Group#stage` |
| 6.11 | A Commit that removes us: no further sending, delete state (SHOULD) | 12.4.2 | done | `#stage` returns `removes_us`, `#merge_commit` makes the group inactive; last epoch's secrets are kept for late messages |
| 6.12 | After a ReInit commit the group MUST NOT be used; wait for the Welcome | 12.4.2 | done | `#merge_commit` makes the group inactive with `pending_reinit`; `Client#reinit_group` creates the successor |
| 6.13 | A member that observed proposals MUST commit before sending application data | 12.4 | done | `#create_application_message` |
| 6.14 | Generating a Commit MUST NOT modify state; Welcome MUST NOT be delivered until the Commit is accepted | 14 | done / *(application)* | `#create_commit` returns a `StagedCommit`; delivery is the caller's |
| 6.15 | After processing a path, outdated key material MUST be deleted | 7.5, 9.2 | done | `EpochSecrets#discard_consumed!`, `PrivateTree#prune!` in `#merge_commit`; retained past epochs keep only their secret tree and sender data secret. Ruby cannot zeroize strings |

## 7. Joining via Welcome (Sections 12.4.3, 12.4.3.1, 12.4.3.3, 13.4)

| # | Requirement | RFC | Status | Code |
|---|---|---|---|---|
| 7.1 | Find the entry for one of our KeyPackages; error if none or if cipher suites differ | 12.4.3.1 | done | `Client#join_group` finds the entry; `Group.from_welcome` compares the KeyPackage's cipher_suite with the Welcome's |
| 7.2 | Error if a PSK in GroupSecrets is unknown | 12.4.3.1 | done | `Group.from_welcome` |
| 7.3 | A resumption PSK with usage reinit or branch MUST be the only such PSK; GroupInfo epoch MUST be 1; reinit/branch consistency checks | 12.4.3.1, 11.2, 11.3 | done | `Group.from_welcome`, `#validate_resumption!`; "same member" is the `member_matcher:` hook *(application)*, identical credentials by default; branch membership is checked against the old group's current tree |
| 7.4 | GroupInfo signature with the signer leaf's key; error if blank or invalid | 12.4.3 | done | `Group.from_welcome` |
| 7.5 | group_id MUST be unique among the groups the client is in | 12.4.3 | done | `Client#ensure_group_id_free!` on create and join |
| 7.6 | GroupInfo cipher_suite matches the KeyPackage's | 12.4.3.1 | done | see 7.1 |
| 7.7 | Tree hash matches GroupContext.tree_hash | 12.4.3.1, 12.4.3.3 | done | `Group.from_welcome` |
| 7.8 | Every non-blank parent node is parent-hash valid | 12.4.3.1, 7.9.2 | done | `#validate_tree!` via `RatchetTree#parent_hash_valid?` |
| 7.9 | Every non-blank leaf valid per 7.3 | 12.4.3.1 | done | `#validate_tree!` -> `#validate_leaf_node!(context: :tree)` |
| 7.10 | unmerged_leaves: each entry is a non-blank descendant leaf; every non-blank node between also lists it; parent encryption keys unique in the tree | 12.4.3.1 | done | `#validate_tree!` |
| 7.11 | Our leaf is the one identical to the KeyPackage's LeafNode | 12.4.3.1 | done | `Group.from_welcome` matches the whole LeafNode |
| 7.12 | Derived private keys MUST correspond to the public keys in the nodes | 12.4.3.1 | done | `#validate_joined_state!` via `PrivateTree#consistent?` |
| 7.13 | Confirmation tag verifies with the derived confirmation key | 12.4.3.1 | done | `Group.from_welcome` |
| 7.14 | Joiner MUST support every GroupContext extension, else the GroupInfo is invalid | 13.4 | done | our own leaf through `#validate_tree!`; a non-default extension we do not list is rejected |
| 7.15 | Unknown GroupInfo.extensions MUST be ignored | 12.4.3, 13.4 | done | only ratchet_tree is looked up |
| 7.16 | ratchet_tree extension: last node non-blank, pad to 2^(d+1)-1 | 12.4.3.3 | done | `RatchetTree.parse`, `#initialize` |
| 7.17 | Download the tree before processing if not in the Welcome | 12.4.3.1 | done | `ratchet_tree:` argument; error if neither |

## 8. Sending side

| # | Requirement | RFC | Status | Code |
|---|---|---|---|---|
| 8.1 | Fresh random 4-byte reuse guard, included in SenderData | 6.3.1 | done | `PrivateMessage.protect` |
| 8.2 | psk_nonce fresh random of length KDF.Nh | 8.4, 12.1.4 | done | `Group#create_psk_proposal` |
| 8.3 | Proposal list valid when creating a commit | 12.2, 12.4.1 | done | `#validate_proposal_list!` |
| 8.4 | Welcome MUST cover every new member; psks in proposal order | 12.4.1 | done | `#create_welcome` |
| 8.5 | Creator MUST pick the best version/cipher suite supported by all added members | 11 | partial | one suite per group; 4.1 covers the check that an added KeyPackage matches it |
| 8.6 | Adding a member: its capabilities MUST cover each GroupContext extension and required_capabilities | 13.4, 11.1 | done | `#validate_key_package!` on `#create_add_proposal` |
| 8.7 | Lifetime of a KeyPackage leaf checked against the current time when sending an Add | 7.3 | done | see 5.5 |
| 8.8 | Capabilities content (see 4.10) | 7.2 | done | `Melos::Capabilities` |

## 9. Wire format

| # | Requirement | RFC | Status | Code |
|---|---|---|---|---|
| 9.1 | Variable-length vector headers MUST use the minimum length; prefix 3 is invalid | 2.1.2 | done | `Melos::Vec.parse_stream`; truncated input raises `ArgumentError` too |
| 9.2 | Any list of extensions MUST NOT contain two of the same type | 13.4 | done | `Extension.check_unique_types!` on join, creation, GroupContextExtensions proposals and Adds; the commit path leaf is covered by tier 3 |
| 9.3 | version fields (MLSMessage, KeyPackage, GroupContext) are mls10 | 6, 8.1, 10 | done | `Group` entry points, see 1.11, 4.1, 4.7 |
| 9.4 | Node hash input optional present iff node non-blank | 7.8 | done by construction | `RatchetTree#tree_hash` |

## Suggested order

1. ~~**Cheap and self-contained**: 1.6 padding, 1.11/9.3 version fields, 9.2 duplicate extensions, 2.4 blank Remove, 2.5 nonce length, 2.10 unknown proposal types, 4.10 Capabilities bug, 6.13 commit-before-send, 6.11 detect our own removal.~~ Done in aee3c38, plus 3.3, 4.1, 4.7 and the 9.1 vector checks.
2. ~~**Commit integrity**: 6.5 to 6.9 (path leaf validation, key uniqueness, parent hash check, per-node ciphertext counts), then the proposal list rules 3.2 to 3.8 and 3.11, shared by `create_commit` and `stage`.~~ Done.
3. ~~**KeyPackage and LeafNode validation**: sections 4 and 5 as one `LeafNode` validator parameterized by context (key_package / update / commit / tree), used by Add processing, commit path processing and join; includes signature, source, extension and capability checks, key uniqueness. Credential validation and maximum lifetime become hooks with defaults.~~ Done.
4. ~~**Join integrity**: 7.8 to 7.12 and 7.14 on top of the validator from step 3.~~ Done.
5. ~~**Client-level**: 7.5 group_id uniqueness, 7.1 KeyPackage suite check.~~ Done.
6. **Later, with the features they belong to**: ~~external senders (1.2, 2.9)~~, ~~resumption PSK rules (2.6, 7.3), ReInit~~, external commits, ~~old-epoch application messages (1.10), deletion schedule (6.15)~~.
