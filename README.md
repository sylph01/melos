# Melos


[![Gem Version](https://badge.fury.io/rb/melos.svg)](https://badge.fury.io/rb/melos)

a [Messaging Layer Security Protocol](https://www.rfc-editor.org/rfc/rfc9420.html) implementation in Ruby

(yes, [an mls gem](https://rubygems.org/gems/mls) happened to exist since 2014, so...)

## Note on implementation status

As of version 0.0.2, this implements:

- Serialization/deserialization of messages
- Key Schedule
- Encryption Secret Tree
- Applying Add/Update/Remove/PreSharedKey/GroupContextExtensions Proposal types
- **✅ Creating messages** (NEW!)
- (thus passes all test vectors in [mls-implementations/test-vectors.md](https://github.com/mlswg/mls-implementations/blob/main/test-vectors.md))

### Message Creation Support

The library now includes comprehensive message creation functionality:

- **`Melos::MessageFactory`** - High-level API for creating application, proposal, and commit messages
- **`Melos::ProposalFactory`** - Convenience methods for creating all proposal types
- **`Melos::GroupState`** - Manages group context for message creation
- **Creation methods** - All message structures now have `self.create` factory methods

Example usage:
```ruby
# Create a remove proposal
proposal = Melos::ProposalFactory.create_remove_proposal(removed_leaf_index: 5)

# Create a proposal message (requires group state)
message = Melos::MessageFactory.create_proposal_message(
  group_state: group_state,
  proposal: proposal
)
```

### Testing

The message creation functionality includes comprehensive tests:

```bash
# Run all message creation tests
ruby -I lib test/run_message_creation_tests.rb

# Run individual test suites
ruby -I lib test/test_proposal_factory.rb     # ProposalFactory tests
ruby -I lib test/test_message_creation.rb     # Creation method tests
ruby -I lib test/test_group_state.rb          # GroupState tests
ruby -I lib test/test_message_factory.rb      # MessageFactory tests

# Run original tests to ensure no regressions
ruby -I lib test/test_messages.rb
```

### Still lacking (not a complete list):

- Applying ReInit/ExternalInit proposals
- Validation (rejecting error cases)
