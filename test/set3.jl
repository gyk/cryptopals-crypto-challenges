using Test
using CryptopalsCryptoChallenges.Set3

using Base64: base64decode

import ..Set3.CbcPaddingOracle
const CPO = CbcPaddingOracle
@testset "cbc_padding_oracle" begin
    STRINGS = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ]

    server = CPO.Server()
    plaintext = Vector{UInt8}(rand(STRINGS, 1)[1])
    (ciphertext, iv) = CPO.encrypt_random(server, copy(plaintext))
    cracked = CPO.crack(server, ciphertext, iv)
    @test plaintext == cracked
end

@testset "ctr_stream_cipher" begin
    ciphertext = base64decode(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    key = b"YELLOW SUBMARINE"
    nonce = 0
    plaintext = aes_128_ctr(ciphertext, key, nonce)
    @test plaintext == b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    @test ciphertext == aes_128_ctr(plaintext, key, nonce)
end

# C19 is the same as C20.
const break_fixed_nonce_ctr_subs = break_fixed_nonce_ctr_stat
@testset "break_fixed_nonce_ctr_subs" begin
    plaintext_list = open("assets/challenge19.txt") do file
        base64decode.(readlines(file))
    end

    min_len  = minimum(length.(plaintext_list))
    plain_min_len = [String(plaintext[1:min_len]) for plaintext in plaintext_list]

    key = rand(UInt8, 16)
    NONCE = 0
    ciphertext_list = [aes_128_ctr(plaintext, key, NONCE) for plaintext in plaintext_list]

    xor_key = break_fixed_nonce_ctr_subs(ciphertext_list)
    cracked_min_len = [
        String(ciphertext[1:min_len] .⊻ xor_key[1:min_len]) for ciphertext in ciphertext_list
    ]

    @test all(lowercase.(cracked_min_len) .== lowercase.(plain_min_len))
end

# NOTE: This test fails with a small chance.
@testset "break_fixed_nonce_ctr_stat" begin
    plaintext_list = open("assets/challenge20.txt") do file
        base64decode.(readlines(file))
    end

    min_len  = minimum(length.(plaintext_list))
    plain_min_len = [String(plaintext[1:min_len]) for plaintext in plaintext_list]

    key = rand(UInt8, 16)
    NONCE = 0
    ciphertext_list = [aes_128_ctr(plaintext, key, NONCE) for plaintext in plaintext_list]

    xor_key = break_fixed_nonce_ctr_stat(ciphertext_list)
    cracked_min_len = [
        String(ciphertext[1:min_len] .⊻ xor_key[1:min_len]) for ciphertext in ciphertext_list
    ]

    res = lowercase.(cracked_min_len) .== lowercase.(plain_min_len)
    if all(res)
        @test true
    else
        true_percentage = sum(res) / length(res)
        println("Correctly cracked chance = ", true_percentage)
        @test true_percentage > 0.9
    end
end
