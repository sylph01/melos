require 'minitest'
include Minitest::Assertions

class << self
  attr_accessor :assertions
end
self.assertions = 0

load 'vec.rb'

u8 = [8].pack('C')
u16 = [65535].pack('S>')
u32 = [65536].pack('L>')

str_vec = ('vec' * 30).to_vec

enc_label = 'label'.to_vec
enc_context = ('context' * 30).to_vec
enc_str = enc_label + enc_context
enc_ctx = MLSStruct::EncryptContext.new(enc_str)
assert_equal enc_ctx.raw, enc_str

puts 'EncryptContext'

cred1_type = [1].pack('S>')
cred1_ident = '[]dentity'.to_vec
cred1_content = cred1_type + cred1_ident
cred1 = MLSStruct::Credential.new(cred1_content)
assert_equal cred1.raw , cred1_content

cred2_type = [2].pack('S>')
cred2_certs = ['cert1', 'cert2cert2', 'cert3cert3cert3'].map(&:to_vec).join.to_vec
cred2_content = cred2_type + cred2_certs
cred2 = MLSStruct::Credential.new(cred2_content)
assert_equal cred2.raw , cred2_content

puts 'Credential'

# basic sender
sender1_type = [1].pack('C')
sender1_leaf_index = [1].pack('L>')
sender1_body = sender1_type + sender1_leaf_index
sender1 = MLSStruct::Sender.new(sender1_body)
assert_equal sender1.raw, sender1_body

puts 'Sender'

# basic framed content
bfc1_group_ids = 'groupid1'.to_vec
bfc1_epoch     = [0xff].pack('Q>')
bfc1_sender    = sender1.raw
bfc1_auth_data = 'authdata1authdata1'.to_vec
bfc1_content_type = [1].pack('C')
bfc1_application_data = 'appdata1appdata1appdata1'.to_vec
bfc1_body = [bfc1_group_ids, bfc1_epoch, bfc1_sender, bfc1_auth_data, bfc1_content_type, bfc1_application_data].join
bfc1 = MLSStruct::FramedContent.new(bfc1_body)
assert_equal bfc1.raw, bfc1_body

puts 'all assertions passed'
