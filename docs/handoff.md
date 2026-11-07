# Handoff: state of melos as of 2026-11-07

For the next working session. Everything below is on `origin/main` at `e7ed812`.

## Where things stand

melos is a Ruby implementation of RFC 9420 (MLS). Version 0.1.0 in the code, not yet released to
RubyGems (`bundle exec rake release` would tag and push it). All mls-implementations test vectors
pass; a round-trip test drives several members against each other with no vectors.

Read these two files first:

- `docs/validation.md`: every MUST-level requirement of RFC 9420 mapped to the code. One `missing`
  row remains (resumption PSK usage, roadmap item 10); the rest are done, partial, or belong to
  features not implemented yet.
- `docs/roadmap.md`: the missing features, ordered by effort. Items 1 to 5 are done. **Item 6 is next.**

## Layout

```
lib/melos.rb                  requires everything (stringio and errors first)
lib/melos/errors.rb           Melos::Error > ProtocolError | StateError | UnsupportedError
lib/melos/crypto.rb           CipherSuite (hpke gem 1.0 underneath), sign/verify/encrypt/decrypt with labels, key (de)serialization
lib/melos/vec.rb              variable-length vectors (2.1.2), rejects non-minimal and truncated input
lib/melos/struct/base.rb      STRUCT-driven (de)serialization; `create(**fields)`; select fields; external context for a child struct
lib/melos/struct/structs.rb   every RFC struct; MLSMessage.create; LeafNode/KeyPackage/GroupInfo sign+verify
lib/melos/tree.rb             pure node-index math (Appendix C)
lib/melos/ratchet_tree.rb     Melos::RatchetTree: the public tree, always full (power-of-two leaves), hashes, parent hashes, TreeKEM
lib/melos/private_tree.rb     Melos::PrivateTree: a member's HPKE private keys by node index; set_path_secret, consistent?, prune!
lib/melos/secret_tree.rb      Melos::SecretTree with a Ratchet per leaf for handshake and application keys
lib/melos/epoch_secrets.rb    Melos::EpochSecrets: one epoch's key schedule; from_joiner / from_init_secret / next; export; discard_consumed!
lib/melos/psk.rb              psk_secret from a list of [PreSharedKeyID.raw, psk]
lib/melos/group.rb            Melos::Group: one member's view of one group (see below)
lib/melos/group/validation.rb all validators (reopens Melos::Group; private methods)
lib/melos/key_package_bundle.rb a published KeyPackage with its init and leaf private keys
lib/melos/client.rb           Melos::Client: identity, external PSK store, KeyPackageBundle store, groups; create_group / join_group
lib/melos/capabilities.rb     default Capabilities (lists no default proposal/extension types, per 7.2)
```

`Melos::Group` in one paragraph: state is suite, group_id, epoch, own leaf_index, signature private
key, `RatchetTree`, `PrivateTree`, extensions, confirmed/interim transcript hashes, the epoch's
`EpochSecrets`, resumption PSKs by epoch, external PSKs (shared by reference with the Client),
pending proposals by ProposalRef, pending Update private keys by public key, and an `active?` flag.
`group_context` is derived. Receiving: `unprotect` → `process_message` → `process_proposal` /
`process_commit` = `merge_commit(stage_commit(ac))`. Sending: `protect`, `create_application_message`,
`create_proposal` (+ `create_add_proposal`, `create_remove_proposal`, `create_psk_proposal`,
`create_update_proposal`), `create_commit(path: :always | :if_required)` → `CommitResult(commit,
welcome, staged)`; the caller merges `result.staged` once the DS accepts the commit. Both sides of a
commit go through the private `stage(ac, own_path:)`.

## Tests

- `bundle exec rake test` runs a subset; `TEST_ALL=1 bundle exec rake test` runs every vector and
  every cipher suite (about a minute). Run the full form before committing.
- Test files are plain scripts with `include Minitest::Assertions`; a failed assertion aborts the
  run. Vectors live in `test_vectors/`.
- `test/test_group_roundtrip.rb`: Alice, Bob, Carol, Dave; add, join, messages, Updates, path-less
  commits, PSK, removal, exporters, deletion schedule. Members exchange `MLSMessage` bytes via
  `wire(message)` = `MLSMessage.new(message.raw)`.
- `test/test_validation.rb`: every rejection, built from crafted inputs. New negative tests go
  before the marker line `## 12.4.2 a member removed by a commit cannot follow the group further`
  (Bob is inactive after it). `C = Melos::Constants` there.
- Ruby 4.0.7 via asdf; gems installed. `bundle exec ruby -Ilib test/test_validation.rb` runs one file.

## Decisions taken (and why)

- The ratchet tree is kept full in memory (2^(d+1)-1 nodes); `raw` strips trailing blanks and
  `parse` rejects a trailing blank (7.7, 12.4.3.3). The old 2n-1 array walked parents past its end.
- `RatchetTree#create_update_path` receives the provisional GroupContext without a tree hash and
  fills in the post-merge hash itself, since the path secrets are encrypted with it (12.4.2).
- Errors: `ProtocolError` = input the RFC says to reject; `StateError` = cannot do this now
  (removed, proposals pending, missing PSK, group_id in use, consumed generation);
  `UnsupportedError` = roadmap feature; plain `ArgumentError` = caller misuse.
- `credential_validator:` defaults to accepting basic credentials only; the application supplies
  an AS check for anything else (5.3.1).
- `max_leaf_node_lifetime:` has **no default**: the interop vectors use 0..2^64-1 lifetimes, so any
  finite default rejects them. 7.2 puts the choice on the application.
- "Same client" in 12.2 (duplicate Adds, Add of a current member) = same signature key.
- A member that was removed becomes inactive: `process_message` and all sending raise `StateError`;
  `unprotect` still works for late messages of the last epoch. Removal is detected from the Remove
  proposals, not from the leaf being blank (an Add in the same commit may reuse the index).
- A committer's own Update is left out of its commit (12.2); the path replaces the leaf.
- Deletion schedule: `EpochSecrets#discard_consumed!` at creation/join/merge; `PrivateTree#prune!` at
  merge; a ratchet generation is handed out once (so replay fails). Ruby cannot zeroize strings.
- Every `Melos::Struct::Base` subclass has `create(**fields)`; structs whose select depends on an
  enclosing struct (FramedContentAuthData, PrivateMessageContent) are parsed with external context:
  `Klass.new(stream, content_type: ...)`.

## Next: roadmap item 6, out-of-order and old-epoch application messages (M)

RFC 9.1, 15.3, 12.4.2. Sketch agreed in the roadmap:

- `SecretTree::Ratchet`: keep a `Hash` of skipped `generation => [key, nonce]` when
  `ratchet_until` jumps forward; serve a requested generation from it and delete it on use; two
  options, a maximum number of kept keys and a maximum forward jump per message (reject beyond,
  15.3's DoS note). Item 5 made a consumed generation raise `StateError`; keep that for generations
  that were actually used.
- `Group`: keep the `EpochSecrets` of the last N epochs in `@past_epochs` (option, small default);
  `unprotect` selects the epoch by `PrivateMessage.epoch` for **application** messages only; handshake
  messages stay current-epoch only. `discard_consumed!` still applies to retained epochs; they are
  dropped when they age out.
- Tests: two application messages delivered in reverse order; an application message from the
  previous epoch delivered after a commit; a generation jump beyond the bound rejected; a replay
  still rejected.
- `docs/validation.md` row 1.10 describes the current stricter behavior; update it.

After 6: 7 external senders, 8 persistence, 10 ReInit/branching, 11 external commits, 9 X.509,
12 interop (gRPC harness from mls-implementations; can start any time now).

## Working conventions used so far

- One commit per milestone, full suite green before each; commit messages explain the RFC
  sections involved; `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` trailer.
- Mark finished items in `docs/roadmap.md` (and rows in `docs/validation.md`) in the same or the
  following commit.
- Push only when asked.
- The RFC text was read from https://www.rfc-editor.org/rfc/rfc9420.txt (sections 6, 7.3, 10.1,
  12.1 to 12.4.3.3, 13.4 are the validation-heavy ones).
