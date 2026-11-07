# Melos


[![Gem Version](https://badge.fury.io/rb/melos.svg)](https://badge.fury.io/rb/melos)

a [Messaging Layer Security Protocol](https://www.rfc-editor.org/rfc/rfc9420.html) implementation in Ruby

(yes, [an mls gem](https://rubygems.org/gems/mls) happened to exist since 2014, so...)

## Implementation status

As of version 0.1.0, this implements:

- Serialization and deserialization of the RFC 9420 structures
- Key schedule, secret tree, pre-shared keys, transcript hashes
- The ratchet tree: TreeKEM (creating and processing UpdatePaths), tree hashes, parent hashes
- Groups: creating a group, Add / Remove / PreSharedKey / GroupContextExtensions proposals,
  commits with an UpdatePath and the matching Welcome, joining via Welcome,
  application messages as PrivateMessage, handshake messages as PublicMessage or PrivateMessage
- Update proposals, commits without an UpdatePath where the RFC allows them, exporters
- The deletion schedule of Section 9.2 (as far as Ruby allows: references are dropped, strings are not zeroized)
- External senders and new-member proposals (`Melos::ExternalSender`, `Client#create_new_member_proposal`)
- Resumption PSKs, ReInit (`Group#create_reinit_proposal`, `Client#reinit_group`) and subgroup branching (`Client#branch_group`)
- Saving and restoring client and group state (`to_h` / `from_h`, JSON through `Melos::Persistence`)
- Out-of-order application messages and messages from recent epochs, with bounds on both (Section 15.3)
- Most MUST-level validations of the RFC; [docs/validation.md](docs/validation.md) maps each one to the code
- All test vectors in [mls-implementations/test-vectors.md](https://github.com/mlswg/mls-implementations/blob/main/test-vectors.md),
  plus round-trip tests in which several members create, join, message and leave a group

It does not yet implement:

- External commits (ExternalInit)
- Credential validation beyond basic credentials (an application hook, `credential_validator:`, is provided)
- Interop testing against other implementations

## Usage

Messages cross between members as `Melos::Struct::MLSMessage` objects; `raw` gives the bytes to
send and `Melos::Struct::MLSMessage.new(bytes)` parses them.

```ruby
require 'melos'

# cipher suite 1 is MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
alice = Melos::Client.new(1, identity: 'alice')
bob   = Melos::Client.new(1, identity: 'bob')

# Bob publishes a KeyPackage
bob_key_package = bob.create_key_package

# Alice creates a group and adds Bob
group = alice.create_group("some group id")
group.create_add_proposal(bob_key_package.message)
result = group.create_commit
# result.commit is the Commit to send to the group, result.welcome the Welcome for Bob;
# merge once the Delivery Service has accepted the commit
group.merge_commit(result.staged)

# Bob joins
bob_group = bob.join_group(result.welcome)

# and talks
message = bob_group.create_application_message("hello")
group.process_message(message).content.application_data # => "hello"
```

`Melos::Group` holds one member's view of one group. `Melos::Client` holds the long-lived identity,
the external PSKs and the KeyPackages it has published.

State can be saved and restored, which a client must do to avoid reusing nonces after a restart
(RFC 9420 6.3.1). The state holds private keys; encrypting it at rest is up to the application.

```ruby
json = Melos::Persistence.dump_client(alice)  # or alice.to_h, for Marshal or MessagePack
alice = Melos::Persistence.load_client(json)  # pass credential_validator: etc. again here
```

## Tests

```
bundle exec rake test
```

runs a subset of the test vectors; `TEST_ALL=1 bundle exec rake test` runs all of them, for every cipher suite.
The vectors are the ones from [mls-implementations](https://github.com/mlswg/mls-implementations), in `test_vectors/`.
