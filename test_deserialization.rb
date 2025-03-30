require 'json'
deserialization_vectors = JSON.parse(File.read('test_vectors/deserialization.json'))

require_relative 'vec_base'

deserialization_vectors.each do |v|
  header = [v['vlbytes_header']].pack('H*')
  length = read_varint(header)
  puts length
  puts v['length']
  puts write_varint(length).unpack1('H*')
  puts v['vlbytes_header']
  puts
end
