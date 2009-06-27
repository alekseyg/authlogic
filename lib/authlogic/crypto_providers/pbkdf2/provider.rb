module Authlogic
  module CryptoProviders
    # = Pbkdf2
    #
    # Uses the Pbkdf2 algorithm to encrypt passwords.
    module Pbkdf2
      class Provider
        class << self
          attr_accessor :join_token
          
          # The number of iterations of Pbkdf2 to put the password through.
          def iterations
            @iterations ||= 2000
          end
          attr_writer :iterations
          
          # Underlying hash function for Pbkdf2 to use (Sha256 by default)
          # $ openssl list-message-digest-commands #list supported hash functions
          def hash_function
            @hash_function ||= 'sha256'
          end
          attr_writer :hash_function
          
          # Turns your raw password into a hash.
          def encrypt(*tokens)
            Authlogic::CryptoProviders::Pbkdf2::Base.new(
              :salt => tokens.pop,
              :password => tokens.join,
              :iterations => iterations,
              :hash_function => hash_function
            ).hex_string
          end
          
          # Does the crypted password match the tokens? Uses the same tokens that were used to encrypt.
          def matches?(crypted, *tokens)
            encrypt(*tokens) == crypted
          end
        end
      end
    end
  end
end
