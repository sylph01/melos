require 'json'
require 'minitest'
require_relative 'structs.rb'
include Minitest::Assertions

class << self
attr_accessor :assertions
end
self.assertions = 0

def from_hex(hex)
  [hex].pack('H*')
end

def to_hex(bin)
  bin.unpack1('H*')
end

message_vectors = JSON.parse(File.read('test_vectors/messages.json'))

message_vector = message_vectors.first

# add_proposal = MLSStruct::Add.new(from_hex(message_vector["add_proposal"]))
# assert_equal to_hex(add_proposal.raw), message_vector["add_proposal"]
# puts "add_proposal"

# update_proposal = MLSStruct::Update.new(from_hex(message_vector["update_proposal"]))
# assert_equal to_hex(update_proposal.raw), message_vector["update_proposal"]
# puts "update_proposal"

# remove_proposal = MLSStruct::Remove.new(from_hex(message_vector["remove_proposal"]))
# assert_equal to_hex(remove_proposal.raw), message_vector["remove_proposal"]
# puts "remove_proposal"

# pre_shared_key_proposal = MLSStruct::PreSharedKey.new(from_hex(message_vector["pre_shared_key_proposal"]))
# assert_equal to_hex(pre_shared_key_proposal.raw), message_vector["pre_shared_key_proposal"]
# puts "pre_shared_key_proposal"

# re_init_proposal = MLSStruct::ReInit.new(from_hex(message_vector["re_init_proposal"]))
# assert_equal to_hex(re_init_proposal.raw), message_vector["re_init_proposal"]
# puts "re_init_proposal"

# external_init_proposal = MLSStruct::ExternalInit.new(from_hex(message_vector["external_init_proposal"]))
# assert_equal to_hex(external_init_proposal.raw), message_vector["external_init_proposal"]
# puts "external_init_proposal"

# group_context_extensions_proposal = MLSStruct::GroupContextExtensions.new(from_hex(message_vector["group_context_extensions_proposal"]))
# assert_equal to_hex(group_context_extensions_proposal.raw), message_vector["group_context_extensions_proposal"]
# puts "group_context_extensions_proposal"

# puts

commit = MLSStruct::Commit.new(from_hex(message_vector["commit"]))
assert_equal to_hex(commit.raw), message_vector["commit"]
puts "commit"

group_secrets = MLSStruct::GroupSecrets.new(from_hex(message_vector["group_secrets"]))
assert_equal to_hex(group_secrets.raw), message_vector["group_secrets"]
puts "group_secrets"
