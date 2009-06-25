require File.dirname(__FILE__) + '/../test_helper.rb'

module CryptoProviderTest
  class Pbkdf2Test < ActiveSupport::TestCase
    def test_encrypt
      assert Authlogic::CryptoProviders::Pbkdf2.encrypt("mypass")
    end
    
    def test_matches
      hash = Authlogic::CryptoProviders::Pbkdf2.encrypt("mypass")
      assert Authlogic::CryptoProviders::Pbkdf2.matches?(hash, "mypass")
    end
  end
end