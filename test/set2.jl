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
    iv = rand(UInt8, 16)
    deciphered = aes_128_cbc_decode(ciphered, key, iv)
    deciphered

    expected = Set2._aes_128_cbc_decode(ciphered, key, iv)
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

import ..Set2.ByteAtATimeEcbDecryptionSimple
const Simple = ByteAtATimeEcbDecryptionSimple
@testset "byte_at_a_time_ecb_decryption_simple" begin
    using Base64: base64decode

    secret = open("assets/challenge12.txt") do file
        base64decode(join(readlines(file)))
    end

    encryption_oracle = Simple.create_enc_oracle(secret)
    @test Simple.byte_at_a_time_ecb_decrypt_simple(encryption_oracle) == String(secret)
end

import ..Set2.EcbCutAndPaste
const ECP = EcbCutAndPaste
@testset "ecb_cut_and_paste" begin
    user = "foo@bar.com"
    user_profile = ECP.profile_for(user)
    svr = ECP.Server()
    enc_user_profile = ECP.encrypt_user_profile(svr, user_profile)
    @assert !ECP.is_admin(ECP.decrypt_user_profile(svr, enc_user_profile))

    enc_admin_profile = ECP.lift_to_admin(enc_user_profile, svr)
    @test ECP.is_admin(ECP.decrypt_user_profile(svr, enc_admin_profile))
end

@testset "pkcs7_validate" begin
    ice = Vector{UInt8}("ICE ICE BABY\x04\x04\x04\x04")
    pkcs7_remove!(ice)
    @test ice == b"ICE ICE BABY"

    bad_ice = Vector{UInt8}("ICE ICE BABY\x05\x05\x05\x05")
    @test_throws InvalidPKCSPaddingException pkcs7_remove!(bad_ice)

    worse_ice = Vector{UInt8}("ICE ICE BABY\x01\x02\x03\x04")
    @test_throws InvalidPKCSPaddingException pkcs7_remove!(worse_ice)

    # Other edge cases
    data = UInt8[1]
    pkcs7_remove!(data)
    @test data == UInt8[]

    data = UInt8[100, 100]
    @test_throws InvalidPKCSPaddingException pkcs7_remove!(data)

    data = UInt8[]
    @test_throws BoundsError pkcs7_remove!(data)
end

import ..Set2.ByteAtATimeEcbDecryptionHarder
const Harder = ByteAtATimeEcbDecryptionHarder
@testset "byte_at_a_time_ecb_decryption_harder" begin
    using Base64: base64decode

    # Reuses the secret from Challenge 12
    secret = open("assets/challenge12.txt") do file
        base64decode(join(readlines(file)))
    end

    encryption_oracle = Harder.create_enc_oracle(secret)
    @test Harder.byte_at_a_time_ecb_decrypt_harder(encryption_oracle) == String(secret)
end

import ..Set2.CbcBitflippingAttacks
const CBA = CbcBitflippingAttacks
@testset "cbc_bitflipping_attacks" begin
    svr = CBA.Server()
    CBA.make_fake_admin(svr)
    enc_admindata = CBA.make_fake_admin(svr)
    @test CBA.is_admin(CBA.decrypt_userdata(svr, enc_admindata))
end
