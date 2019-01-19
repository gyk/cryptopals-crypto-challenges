using Test
using CryptopalsCryptoChallenges.Set1

@testset "convert_hex_to_base64" begin
    hex_bytes = Vector{UInt8}(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f" *
        "69736f6e6f7573206d757368726f6f6d")
    b64_bytes = hex2base64(hex_bytes)
    @test b64_bytes == Vector{UInt8}(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
end

@testset "fixed_xor" begin
    buffer1 = hex2bytes("1c0111001f010100061a024b53535009181c")
    buffer2 = hex2bytes("686974207468652062756c6c277320657965")
    expected = hex2bytes("746865206b696420646f6e277420706c6179")
    @test fixed_xor(buffer1, buffer2) == expected
end

@testset "single_byte_xor_cipher" begin
    ciphered = hex2bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    deciphered = single_byte_xor_decrypt(ciphered).plaintext
    @test deciphered == "Cooking MC's like a pound of bacon"
end

@testset "detect_single_character_xor" begin
    lines_byte = open("assets/challenge4.txt") do file
        hex2bytes.(readlines(file))
    end

    deciphered = detect_single_byte_xor(lines_byte)
    @test deciphered == "Now that the party is jumping\n"
end

@testset "repeating_key_xor" begin
    plaintext = b"""
        Burning 'em, if you ain't quick and nimble
        I go crazy when I hear a cymbal"""
    key = b"ICE"
    secret = repeating_key_xor(plaintext, key)
    @test bytes2hex(secret) ==
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" *
        "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    input = UInt8.(plaintext)
    repeating_key_xor!(input, key)  # Now `secret` is stored in `input`
    @test input == secret
end

@testset "break_repeating_key_xor" begin
    @test bit_hamming_distance(b"this is a test", b"wokka wokka!!!") == 37

    using Base64: base64decode

    ciphered = open("assets/challenge6.txt") do file
        base64decode(join(readlines(file)))
    end

    plaintext = open("assets/vanilla-ice.txt") do file
        read(file, String)
    end

    key = break_repeating_key_xor(ciphered)
    @test strip(String(repeating_key_xor(ciphered, key))) == strip(plaintext)
end

@testset "aes_in_ecb_mode" begin
    using Base64: base64decode

    ciphered = open("assets/challenge7.txt") do file
        base64decode(join(readlines(file)))
    end

    plaintext = open("assets/vanilla-ice.txt") do file
        read(file, String)
    end

    key = b"YELLOW SUBMARINE"
    deciphered = aes_128_ecb_decode(ciphered, key)
    @test strip(String(deciphered), ['\x04']) == plaintext  # strips padding
end

@testset "detect_aes_in_ecb_mode" begin
    cipher = open("assets/challenge8.txt") do file
        hex2bytes.(readlines(file))
    end
    @test detect_aes_ecb(cipher) == 133
end
