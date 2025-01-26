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

hg = MLSStruct::Hoge.new(str_vec)
assert_equal hg.raw, str_vec

hg, hg_rest = MLSStruct::Hoge.new_and_rest(str_vec)

enc_label = 'label'.to_vec
enc_context = ('context' * 30).to_vec
enc_str = enc_label + enc_context
enc_ctx = MLSStruct::EncryptContext.new(enc_str)
assert_equal enc_ctx.raw, enc_str

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

kl = MLSStruct::Klass.new(str_vec + str_vec)
assert_equal kl.raw, str_vec + str_vec

kls_raw = ['foo', 'bar', 'baz', 'qux', 'quux'].map(&:to_vec).join.to_vec
kls = MLSStruct::Klasses.new(kls_raw)
assert_equal kls.raw, kls_raw

puts 'all assertions passed'