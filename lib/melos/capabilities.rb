class Melos::Capabilities
  attr_accessor :versions, :cipher_suites, :extensions, :proposals, :credentials

  def initialize
    set_default
  end

  def set_default
    @versions = [1]
    @cipher_suites = [1, 2, 3, 4, 5, 6, 7]
    @extensions = [] # 7.2: likewise the default extension types
    @proposals = [] # 7.2: the default proposal types (add .. group_context_extensions) MUST NOT be listed
    @credentials = [1]
  end
end