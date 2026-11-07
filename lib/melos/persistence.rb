require 'json'

# Turning the state Hashes of Melos::Client#to_h and Melos::Group#to_h into JSON and back.
# Those Hashes have Symbol keys, and their Strings are binary; here every String becomes hex and every
# key a JSON string, and the reverse on load. Marshal, MessagePack or anything else that keeps
# binary Strings works on the Hashes as they are.
#
# The state holds private keys and epoch secrets. Encrypting it at rest is the application's job.
module Melos::Persistence
  extend self

  def dump_json(hash)
    JSON.generate(encode(hash))
  end

  def load_json(json)
    decode(JSON.parse(json))
  end

  def dump_client(client) = dump_json(client.to_h)
  def load_client(json, **group_options) = Melos::Client.from_h(load_json(json), **group_options)
  def dump_group(group) = dump_json(group.to_h)
  def load_group(json, **options) = Melos::Group.from_h(load_json(json), **options)

  private

  def encode(value)
    case value
    when Hash then value.to_h { |key, v| [key.to_s, encode(v)] }
    when Array then value.map { encode(_1) }
    when String then value.unpack1('H*')
    when Integer, true, false, nil then value
    else raise ArgumentError.new("cannot encode #{value.class}")
    end
  end

  def decode(value)
    case value
    when Hash then value.to_h { |key, v| [key.to_sym, decode(v)] }
    when Array then value.map { decode(_1) }
    when String then [value].pack('H*')
    else value
    end
  end
end
