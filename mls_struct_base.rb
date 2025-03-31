module MLSStruct; end

class MLSStruct::Base
  def initialize(buf)
    context, _ = deserialize(buf)
    set_instance_vars(context)
    self
  end

  def self.new_and_rest(buf)
    instance = self.allocate
    context, buf = instance.send(:deserialize, buf)
    instance.send(:set_instance_vars, context)
    [instance, buf]
  end

  def raw
    buf = ''
    self.class::STRUCT.each do |elem|
      case elem[1]
      when :select
        value = self.instance_variable_get("@#{elem[0]}")
        buf += serialize_select_elem(value, elem[3])
      else
        value = self.instance_variable_get("@#{elem[0]}")
        buf += serialize_elem(value, elem[1])
      end
    end
    buf
  end

  def self.vecs(buf)
    value, buf = String.parse_vec(buf)
    array = []
    while (value.bytesize > 0)
      current_instance, value = String.parse_vec(value)
      array << current_instance
    end
    [array, buf]
  end

  # context here takes a hash
  # returns [value, rest_of_buffer]
  # value could return nil, which means predicate was not applicable
  # predicate takes the context and returns true or false
  def deserialize_select_elem_with_context(buf, context, predicate, type, type_param)
    if predicate.(context)
      deserialize_elem(buf, type, type_param)
    else
      [nil, buf]
    end
  end

  private
  def deserialize(buf)
    context = []
    self.class::STRUCT.each do |elem|
      case elem[1]
      when :select
        value, buf = deserialize_select_elem_with_context(buf, context.to_h, elem[2], elem[3], elem[4])
        context << [elem[0], value]
      when :framed_content_auth_data
        value, buf = MLSStruct::FramedContentAuthData.new_and_rest_with_content_type(buf, context.to_h[:content].content_type)
        context << [elem[0], value]
      else
        value, buf = deserialize_elem(buf, elem[1], elem[2])
        context << [elem[0], value]
      end
    end
    [context, buf]
  end

  def set_instance_vars(context)
    context.each do |elem|
      self.instance_variable_set("@#{elem[0]}", elem[1])
    end
  end

  def deserialize_elem(buf, type, type_param)
    case type
    when :uint8
      value = buf.byteslice(0, 1).unpack1('C')
      buf = buf.byteslice(1..)
    when :uint16
      value = buf.byteslice(0, 2).unpack1('S>')
      buf = buf.byteslice(2..)
    when :uint32
      value = buf.byteslice(0, 4).unpack1('L>')
      buf = buf.byteslice(4..)
    when :uint64
      value = buf.byteslice(0, 8).unpack1('Q>')
      buf = buf.byteslice(8..)
    when :vec
      value, buf = String.parse_vec(buf)
    when :vecs
      value, buf = MLSStruct::Base.vecs(buf)
    when :class
      value, buf = type_param.send(:new_and_rest, buf)
    when :classes
      # prefix, length = buf.get_prefix_and_length
      # puts "#{prefix}, #{length}"
      vec, buf = String.parse_vec(buf)
      value = []
      while (vec.bytesize > 0)
        current_instance, vec = type_param.send(:new_and_rest, vec)
        value << current_instance
      end
    when :optional
      presence = buf.byteslice(0, 1).unpack1('C')
      buf = buf.byteslice(1..)
      case presence
      when 0
        value = nil
      when 1
        # as of RFC 9420, optional always takes a class
        value, buf = type_param.send(:new_and_rest, buf)
      end
    when :opaque
      value = buf.byteslice(0, type_param.to_i)
      buf = buf.byteslice((type_param.to_i)..)
    end
    [value, buf]
  end

  # take a name and type
  def serialize_elem(value, type)
    case type
    when :uint8
      [value].pack('C')
    when :uint16
      [value].pack('S>')
    when :uint32
      [value].pack('L>')
    when :uint64
      [value].pack('Q>')
    when :vec
      value.to_vec
    when :vecs
      value.map(&:to_vec).join.to_vec
    when :class, :framed_content_auth_data
      value.raw
    when :classes
      value.map(&:raw).join.to_vec
    when :optional
      if value.nil?
        [0].pack('C')
      else
        # as of RFC 9420, optional always takes a class
        [1].pack('C') + value.raw
      end
    when :opaque
      value
    end
  end

  def serialize_select_elem(value, type)
    if value.nil?
      ''
    else
      serialize_elem(value, type)
    end
  end
end
