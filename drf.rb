#!/usr/bin/env ruby

require 'digest/sha2'
require 'openssl/cipher'

module DeterministicRandom
  def self.keygen seed, length
    seed = "#{seed};#{length}"
    hash = Digest::SHA256.hexdigest(seed)
    key = hash[ 0...32]
    iv  = hash[32...48]
    puts "Creating #{length} bytes using [key: #{key}, iv: #{iv}] derived from seed: '#{seed}'"
    [key, iv]
  end

  def self.create mode, key, iv
    aes = OpenSSL::Cipher::AES256.new(:CTR)
    aes.send mode
    aes.key = key
    aes.iv  = iv
    aes
  end

  def self.create_encryptor key, iv ; create :encrypt, key, iv end
  def self.create_decryptor key, iv ; create :decrypt, key, iv end

  # Generates an encrypting generator
  #
  # cipher - must be a stream cipher
  # length - the expected stream length
  #
  # For each call, returns a block of cipher_text up to block_size in length
  #                returns the empty string if the expected length has already been generated 
  def self.generate_encryptor cipher, length
    g = Fiber.new do
      block_size = 16
      block = "\0" * block_size
      remainder = length
      loop do
        next Fiber.yield '' if remainder.zero?
        if remainder >= block_size
          remainder -= block_size
        elsif remainder < block_size
          block = "\0" * remainder
          remainder = 0
        end
        Fiber.yield cipher.update(block)
      end
    end
  end

  # Generates a decrypting generator
  #
  # cipher - must be a stream cipher
  # length - the expected stream length
  #
  # For each block, returns false if the text failed to decrypt properly
  #                 returns :partial_result if it decrypts properly but isn't finished
  #                 returns true if the text fully decrypted
  def self.generate_decryptor cipher, length
    g = Fiber.new do |cipher_text|
      remainder = length
      failed = false
      loop do
        remainder -= cipher_text.length
        if remainder < 0 || failed
          Fiber.yield false
        end
        plaintext = cipher.update cipher_text
        result = plaintext == "\0" * cipher_text.length
        failed = true unless result
        return_value = failed ? false : remainder.zero? ? true : :partial_result
        cipher_text = Fiber.yield(return_value)
      end
    end
  end

  def self.drf seed, length
    key, iv = keygen seed, length
    cipher = create_encryptor key, iv
    encryptor = generate_encryptor cipher, length
  end

  def self.test seed: 'foobar', length: 35, force_fail: false
    # derive a key+iv from the user's seed and file length
    key, iv = keygen seed, length

    # create an encryptor which generates 'length' bytes of cipher_text
    enc_cipher = create_encryptor key, iv
    enc_gen = generate_encryptor enc_cipher, length

    # loop and generate the full cypher text and disk_block (convenient for writing) bytes at a time
    cipher_text = ''
    loop do
      cipher_block = enc_gen.resume
      break if cipher_block.empty?
      p [:cipher_block, cipher_block]
      cipher_text += cipher_block
    end

    # force the test to fail if desired
    cipher_text[0] = (cipher_text[0].ord + 1).chr if force_fail

    p [:cipher_text_length, cipher_text.length, :cipher_text, cipher_text]

    # create an decryptor which checks 'length' bytes of cipher_text
    dec_cipher = create_decryptor key, iv
    dec_gen = generate_decryptor dec_cipher, length

    # loop and check the full cypher text in blocks of disk_block (convenient for reading) at a time
    res = false
    loop do
      break if !cipher_text || cipher_text.empty?
      cipher_block = cipher_text[0...16]
      cipher_text  = cipher_text[16..-1]
      res = dec_gen.resume cipher_block
      p [:res, res, :cipher_block, cipher_block]
    end

    # display the round-trip results
    p [:decryption, res]
    res
  end

  def self.cli args
    seed, length = args
    drf seed, length.to_i
  end
end

if $0 == __FILE__
  DeterministicRandom.cli ARGS
end
