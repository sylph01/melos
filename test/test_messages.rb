require 'json'
require 'minitest'
require 'melos'
include Minitest::Assertions
include Melos::Util

class << self
attr_accessor :assertions
end
self.assertions = 0

if ENV['TEST_ALL']
  message_vectors = JSON.parse(File.read('test_vectors/messages.json'))
else
  message_vectors = JSON.parse(File.read('test_vectors/messages.json'))[0..19]
end

message_vectors.each_with_index do |message_vector, idx|

puts "iteration #{idx}"

add_proposal = Melos::Struct::Add.new(from_hex(message_vector["add_proposal"]))
assert_equal to_hex(add_proposal.raw), message_vector["add_proposal"]
puts "[s] add_proposal"

update_proposal = Melos::Struct::Update.new(from_hex(message_vector["update_proposal"]))
assert_equal to_hex(update_proposal.raw), message_vector["update_proposal"]
puts "[s] update_proposal"

remove_proposal = Melos::Struct::Remove.new(from_hex(message_vector["remove_proposal"]))
assert_equal to_hex(remove_proposal.raw), message_vector["remove_proposal"]
puts "[s] remove_proposal"

pre_shared_key_proposal = Melos::Struct::PreSharedKey.new(from_hex(message_vector["pre_shared_key_proposal"]))
assert_equal to_hex(pre_shared_key_proposal.raw), message_vector["pre_shared_key_proposal"]
puts "[s] pre_shared_key_proposal"

re_init_proposal = Melos::Struct::ReInit.new(from_hex(message_vector["re_init_proposal"]))
assert_equal to_hex(re_init_proposal.raw), message_vector["re_init_proposal"]
puts "[s] re_init_proposal"

external_init_proposal = Melos::Struct::ExternalInit.new(from_hex(message_vector["external_init_proposal"]))
assert_equal to_hex(external_init_proposal.raw), message_vector["external_init_proposal"]
puts "[s] external_init_proposal"

group_context_extensions_proposal = Melos::Struct::GroupContextExtensions.new(from_hex(message_vector["group_context_extensions_proposal"]))
assert_equal to_hex(group_context_extensions_proposal.raw), message_vector["group_context_extensions_proposal"]
puts "[s] group_context_extensions_proposal"

commit = Melos::Struct::Commit.new(from_hex(message_vector["commit"]))
assert_equal to_hex(commit.raw), message_vector["commit"]
puts "[s] commit"

group_secrets = Melos::Struct::GroupSecrets.new(from_hex(message_vector["group_secrets"]))
assert_equal to_hex(group_secrets.raw), message_vector["group_secrets"]
puts "[s] group_secrets"

mls_welcome = Melos::Struct::MLSMessage.new(from_hex(message_vector["mls_welcome"]))
assert_equal to_hex(mls_welcome.raw), message_vector["mls_welcome"]
puts "[s] mls_welcome"

mls_group_info = Melos::Struct::MLSMessage.new(from_hex(message_vector["mls_group_info"]))
assert_equal to_hex(mls_group_info.raw), message_vector["mls_group_info"]
puts "[s] mls_group_info"

mls_key_package = Melos::Struct::MLSMessage.new(from_hex(message_vector["mls_key_package"]))
assert_equal to_hex(mls_key_package.raw), message_vector["mls_key_package"]
puts "[s] mls_key_package"

private_message = Melos::Struct::MLSMessage.new(from_hex(message_vector["private_message"]))
assert_equal to_hex(private_message.raw), message_vector["private_message"]
puts "[s] private_message"

public_message_application = Melos::Struct::MLSMessage.new(from_hex(message_vector["public_message_application"]))
assert_equal to_hex(public_message_application.raw), message_vector["public_message_application"]
puts "[s] public_message_application"

public_message_proposal = Melos::Struct::MLSMessage.new(from_hex(message_vector["public_message_proposal"]))
assert_equal to_hex(public_message_proposal.raw), message_vector["public_message_proposal"]
puts "[s] public_message_proposal"

public_message_commit = Melos::Struct::MLSMessage.new(from_hex(message_vector["public_message_commit"]))
assert_equal to_hex(public_message_commit.raw), message_vector["public_message_commit"]
puts "[s] public_message_commit"

ratchet_tree = Melos::Struct::RatchetTree.parse(from_hex(message_vector["ratchet_tree"]))
assert_equal to_hex(Melos::Struct::RatchetTree.raw(ratchet_tree)), message_vector["ratchet_tree"]
puts "[s] ratchet_tree"

puts
end
