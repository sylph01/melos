## Ratchet Tree Extension (12.4.3.3)
module MLS; end
module MLS::Struct; end

module MLS::Struct::RatchetTree
  def self.parse(vec)
    array, _ = new_and_rest(vec)
    array
  end

  def self.new_and_rest(vec)
    array = []
    buf, rest = String.parse_vec(vec)
    while buf.bytesize > 0
      presence = buf.byteslice(0, 1).unpack1('C')
      buf = buf.byteslice(1..)
      case presence
      when 0
        array << nil
      when 1
        node, buf = MLSStruct::Node.new_and_rest(buf)
        array << node
      end
    end
    [array, rest]
  end

  def self.raw(array)
    buf = ''
    array.each do |optional_node|
      if optional_node.nil?
        buf += [0].pack('C')
      else
        buf += [1].pack('C')
        buf += optional_node.raw
      end
    end

    buf.to_vec
  end
end
