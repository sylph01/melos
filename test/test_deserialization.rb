require 'json'
require 'mls'
require 'minitest'
include Minitest::Assertions

class << self
  attr_accessor :assertions
end
self.assertions = 0

deserialization_vectors = JSON.parse(File.read('test_vectors/deserialization.json'))

deserialization_vectors.each_with_index do |v, idx|
  puts "vector #{idx}:"
  header = [v['vlbytes_header']].pack('H*')
  length = MLS::Vec.read_varint(header)
  assert_equal length, v['length']
  puts "[pass] length matches"

  assert_equal MLS::Vec.write_varint(length).unpack1('H*'), v['vlbytes_header']
  puts "[pass] varint header matches"
end
