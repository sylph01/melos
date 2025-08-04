class Melos::Group
  def initialize(cipher_suite)
    # TODO: check if cipher_suite is defined
    @cipher_suite = cipher_suite
  end
  
  # message is the raw message,
  # key_package is a Melos::Struct::MLSMessage that has a KeyPackage type
  def join_with_welcome(message, key_package)
    message_obj = Melos::Struct::MLSMessage.new(message)
    if message_obj.welcome.nil?
      raise ArgumentError.new('Wrong message type (need a Welcome message)')
    end
    welcome = message_obj.welcome
    kp_ref = key_package.key_package.ref(suite)
    encrypted_group_secrets = welcome.secrets.find { _1.new_member == kp_ref }&.encrypted_group_secrets
    group_secrets = Melos::Struct::GroupSecrets.new(
      Melos::Crypto.decrypt_with_label(
      suite,
      init_priv,
      "Welcome",
      welcome.welcome.encrypted_group_info,
      egs.kem_output,
      egs.ciphertext
      )
    )
  end
end