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

### Still lacking (not a complete list):

- Applying ReInit/ExternalInit proposals
- Validation (rejecting error cases)
