#!/usr/bin/env ruby

require 'digest/sha2'
require 'openssl/cipher'

# DeterministicRandomContent - Generate random content via a cipher so it can be recreated later for checking for data corruption
#
# For a filesystem checker, create random files without obvious patterns of compressability and later check
# the data without having to store it in the interim.
#
module DeterministicRandomContent

  # Tests a round-trip, has ability to force the test to fail
  #
  # length: Total cipher text length
  # seed: The source for the key and iv
  # force_fail: Mutates the first character of the cipher text before decryption
  # block_size: How much cipher text is generated at once
  #
  def self.test seed: 'foobar', length: 35, force_fail: false, block_size: 16
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
      cipher_block = cipher_text[0...block_size]
      cipher_text  = cipher_text[block_size..-1]
      res = dec_gen.resume cipher_block
      p [:res, res, :cipher_block, cipher_block]
    end

    # display the round-trip results
    p [:decryption, res]
    res
  end

  # keygen - Derives the key + iv from the combined seed and length, stretched via sha256
  def self.keygen seed, length
    seed = "#{seed};#{length}"
    hash = Digest::SHA256.digest(seed)
    key = hash
    iv  = Digest::SHA256.digest(hash)[0...16]
    # puts "Creating #{length} bytes using [key: #{key.unpack('H*').first}, iv: #{iv.unpack('H*').first}] derived from seed: '#{seed}'"
    [key, iv]
  end

  # Create stream cipher
  #
  # Creates a stream cipher to allow for arbitrary (not based on a cipher block) content lengths
  def self.create_stream_cipher mode, key, iv
    aes = OpenSSL::Cipher::AES256.new(:CTR)
    aes.send mode
    aes.key = key
    aes.iv  = iv
    aes
  end

  def self.create_encryptor key, iv ; create_stream_cipher :encrypt, key, iv end
  def self.create_decryptor key, iv ; create_stream_cipher :decrypt, key, iv end

  # Generates an encrypting generator
  #
  # cipher - must be a stream cipher
  # length - the expected stream length
  #
  # For each call, returns a block of cipher_text up to block_size in length
  #                returns the empty string if the expected length has already been generated
  def self.generate_encryptor cipher, length, block_size: 16
    g = Fiber.new do
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
  #                 returns :partial_success if it decrypts properly but isn't finished
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
        return_value = failed ? false : (remainder.zero? ? true : :partial_success)
        cipher_text = Fiber.yield(return_value)
      end
    end
  end

  def self.write_file name, length
    key, iv = keygen name, length
    cipher = create_encryptor key, iv
    encryptor = generate_encryptor cipher, length
    File.open(name, 'wb') {|fh|
      while !(block = encryptor.resume).empty?
        fh.write block
      end
    }
    true
  end

  def self.verify_file name
    remainder = length = File.stat(name).size
    key, iv = keygen name, length
    cipher = create_encryptor key, iv
    decryptor = generate_decryptor cipher, length
    File.open(name, 'rb') {|fh|
      while !remainder.zero?
        read_size = [16, remainder].min
        block = fh.read read_size
        result = decryptor.resume(block)
        raise "File verify error at bytes #{(length - remainder) .. (length - remainder +16)}" unless result
        remainder -= read_size
      end
    }
    true
  end

  # cli - called with CLI args, intended for creating files from the shell
  #
  def self.cli args
    seed, length = args
    drf seed, length.to_i
  end
end

if $0 == __FILE__
  DeterministicRandom.cli ARGS
end
