class Melos::Capabilities
  attr_accessor :versions, :cipher_suites, :extensions, :proposals, :credentials

  # credentials: the credential types this client can validate in other members' leaves (13.3); a client
  # that accepts X.509 credentials (Melos::Credential::X509) lists 2 as well as 1
  def initialize(credentials: [Melos::Constants::CredentialType::BASIC])
    set_default
    @credentials = credentials
  end

  def set_default
    @versions = [1]
    @cipher_suites = [1, 2, 3, 4, 5, 6, 7]
    @extensions = [] # 7.2: likewise the default extension types
    @proposals = [] # 7.2: the default proposal types (add .. group_context_extensions) MUST NOT be listed
    @credentials = [1]
  end
end
