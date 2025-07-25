module Melos::Struct; end

class Melos::Struct::Base
  def initialize(stream)
    stream = StringIO.new(stream) if stream.is_a?(String)
    context = deserialize(stream)
    set_instance_vars(context)
    self
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
        buf += serialize_elem(value, elem[1], elem[2])
      end
    end
    buf
  end

  # context here takes a hash
  # returns [value, rest_of_buffer]
  # value could return nil, which means predicate was not applicable
  # predicate takes the context and returns true or false
  def deserialize_select_elem_with_context(stream, context, predicate, type, type_param)
    if predicate.(context)
      deserialize_elem(stream, type, type_param)
    else
      nil
    end
  end

  private
  def deserialize(stream)
    context = []
    self.class::STRUCT.each do |elem|
      case elem[1]
      when :select
        value = deserialize_select_elem_with_context(stream, context.to_h, elem[2], elem[3], elem[4])
        context << [elem[0], value]
      when :framed_content_auth_data
        value = Melos::Struct::FramedContentAuthData.new_with_content_type(stream, context.to_h[:content].content_type)
        context << [elem[0], value]
      else
        value = deserialize_elem(stream, elem[1], elem[2])
        context << [elem[0], value]
      end
    end
    context
  end

  def set_instance_vars(context)
    context.each do |elem|
      self.instance_variable_set("@#{elem[0]}", elem[1])
    end
  end

  def deserialize_elem(stream, type, type_param)
    case type
    when :uint8
      value = stream.read(1).unpack1('C')
    when :uint16
      value = stream.read(2).unpack1('S>')
    when :uint32
      value = stream.read(4).unpack1('L>')
    when :uint64
      value = stream.read(8).unpack1('Q>')
    when :vec
      value = Melos::Vec.parse_stringio(stream)
    when :vec_of_type
      data = Melos::Vec.parse_stringio(stream)
      value = []
      data_stream = StringIO.new(data)
      while (!data_stream.eof?)
        current_instance = deserialize_elem(data_stream, type_param, nil)
        value << current_instance
      end
    when :class
      value = type_param.send(:new, stream)
    when :classes
      data = Melos::Vec.parse_stringio(stream)
      value = []
      data_stream = StringIO.new(data)
      while (!data_stream.eof?)
        current_instance = type_param.send(:new, data_stream)
        value << current_instance
      end
    when :optional
      presence = stream.read(1).unpack1('C')
      case presence
      when 0
        value = nil
      when 1
        # as of RFC 9420, optional always takes a class
        value = type_param.send(:new, stream)
      end
    when :opaque
      value = stream.read(type_param.to_i)
    when :padding
      value = stream.read
    end
    value
  end

  # take a name and type
  def serialize_elem(value, type, type_param)
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
      Melos::Vec.from_string(value)
    when :vec_of_type
      Melos::Vec.from_string(value.map { serialize_elem(_1, type_param, nil) }.join)
    when :class, :framed_content_auth_data
      value.raw
    when :classes
      Melos::Vec.from_string(value.map(&:raw).join)
    when :optional
      if value.nil?
        [0].pack('C')
      else
        # as of RFC 9420, optional always takes a class
        [1].pack('C') + value.raw
      end
    when :opaque
      value
    when :padding
      value
    end
  end

  def serialize_select_elem(value, type)
    if value.nil?
      ''
    else
      serialize_elem(value, type, nil)
    end
  end
end
