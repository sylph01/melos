module Melos::Constants
  module Version
    MLS10 = 0x01
  end

  module WireFormat
    #  17.2. MLS Wire Formats
    MLS_PUBLIC_MESSAGE = 0x0001
    MLS_PRIVATE_MESSAGE = 0x0002
    MLS_WELCOME = 0x0003
    MLS_GROUP_INFO = 0x0004
    MLS_KEY_PACKAGE = 0x0005
  end

  module ExtensionType
    # 17.3. MLS Extension Types
    APPLICATION_ID = 0x0001
    RATCHET_TREE = 0x0002
    REQUIRED_CAPABILITIES = 0x0003
    EXTERNAL_PUB = 0x0004
    EXTERNAL_SENDERS = 0x0005
  end

  module CredentialType
    #  17.5. MLS Credential Types
    BASIC = 0x0001
    X509 = 0x0002
  end

  module ContentType
    APPLICATION = 0x01
    PROPOSAL = 0x02
    COMMIT = 0x03
  end

  module SenderType
    MEMBER = 0x01
    EXTERNAL = 0x02
    NEW_MEMBER_PROPOSAL = 0x03
    NEW_MEMBER_COMMIT = 0x04
  end

  module LeafNodeSource
    KEY_PACKAGE = 0x01
    UPDATE = 0x02
    COMMIT = 0x03
  end

  module ProposalType
    ADD = 0x0001
    UPDATE = 0x0002
    REMOVE = 0x0003
    PSK = 0x0004
    REINIT = 0x0005
    EXTERNAL_INIT = 0x0006
    GROUP_CONTEXT_EXTENSIONS = 0x0007
  end

  module NodeType
    LEAF = 0x01
    PARENT = 0x02
  end

  module PSKType
    EXTERNAL = 0x01
    RESUMPTION = 0x02
  end

  module ResumptionPSKUsage
    APPLICATION = 0x01
    REINIT = 0x02
    BRANCH = 0x03
  end

  module ProposalOrRefType
    PROPOSAL = 0x01
    REFERENCE = 0x02
  end
end
