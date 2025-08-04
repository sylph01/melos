class Melos::Capabilities
  attr_accessor :versions, :cipher_suites, :extensions, :proposals, :credentials

  def initialize
    set_default
  end

  def set_default
    @versions = [1]
    @cipher_suites = [1, 2, 3, 4, 5, 6, 7]
    @extensions = []
    @proposals = [1, 2, 3, 4, 7]
    @credentials = [1]
  end
end