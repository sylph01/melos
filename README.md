# Melos


[![Gem Version](https://badge.fury.io/rb/melos.svg)](https://badge.fury.io/rb/melos)

a [Messaging Layer Security Protocol](https://www.rfc-editor.org/rfc/rfc9420.html) implementation in Ruby

(yes, [an mls gem](https://rubygems.org/gems/mls) happened to exist since 2014, so...)

## Note on implementation status

As of version 0.0.1, this implements:

- Serialization/deserialization of messages
- Key Schedule
- Encryption Secret Tree
- Applying Add/Update/Remove/PreSharedKey/GroupContextExtensions Proposal types
- (thus passes all test vectors in [mls-implementations/test-vectors.md](https://github.com/mlswg/mls-implementations/blob/main/test-vectors.md))

but lacks the following (not a complete list):

- Creating messages
- Applying ReInit/ExternalInit proposals
- Validation (rejecting error cases)
