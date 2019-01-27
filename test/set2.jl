using Test
using CryptopalsCryptoChallenges.Set2

@testset "pkcs7_padding" begin
    text = UInt8.(b"YELLOW SUBMARINE")
    pkcs7_padding!(text, 20)
    expected_after_padding = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    @test text == expected_after_padding

    # Some edge cases
    uint8_8_8 = UInt8[8, 8, 8, 8, 8, 8, 8, 8]
    a = UInt8[]
    pkcs7_padding!(a, 8)
    @test a == uint8_8_8

    uint8_1to8 = collect(UInt8(1):UInt8(8))
    a = copy(uint8_1to8)
    pkcs7_padding!(a, 8)
    @test a == vcat(uint8_1to8, uint8_8_8)
end

@testset "cbc_mode" begin
    using Base64: base64decode

    ciphered = open("assets/challenge10.txt") do file
        base64decode(join(readlines(file)))
    end

    key = b"YELLOW SUBMARINE"
    deciphered = aes_128_cbc_decode(ciphered, key)
    deciphered

    expected = Set2._aes_128_cbc_decode(ciphered, key)
    @test deciphered == expected
end

@testset "ecb_cbc_detection_oracle" begin
    for _ in 1:20
        mode = rand_aes_mode()
        enc_fn = plaintext -> encrypt_by_mode(plaintext, mode)
        detected_mode = ecb_cbc_detection_oracle(enc_fn)
        @test detected_mode == mode
    end
end

@testset "byte_at_a_time_ecb_decryption_simple" begin
    using Base64: base64decode

    secret = open("assets/challenge12.txt") do file
        base64decode(join(readlines(file)))
    end

    encryption_oracle = create_enc_oracle(secret)
    @test byte_at_a_time_ecb_decrypt_simple(encryption_oracle) == String(secret)
end
