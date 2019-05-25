using Test
using CryptopalsCryptoChallenges.Set4

using CryptopalsCryptoChallenges.Set3: aes_128_ctr
@testset "break_random_access_aes_ctr" begin
    # Challenge 25 uses the recovered text from Challenge 7 ('vanilla-ice.txt').
    plaintext = open("assets/vanilla-ice.txt") do file
        Vector{UInt8}(read(file))
    end
    key = rand(UInt8, 16)
    nonce = Int64(0)
    ciphertext = aes_128_ctr(plaintext, key, nonce)

    # The attacker controls the offset and "new text".
    OFFSET = 996
    NEW_TEXT = Vector{UInt8}("Intensive Care Unit")
    new_ciphertext = edit(ciphertext, key, OFFSET, NEW_TEXT)

    @test recover_plaintext(ciphertext, new_ciphertext, OFFSET, NEW_TEXT) ==
        plaintext[OFFSET:(OFFSET + length(NEW_TEXT) - 1)]
end

import ..Set4.CtrBitflippingAttacks
const CtrBA = CtrBitflippingAttacks
@testset "ctr_bitflipping_attacks" begin
    svr = CtrBA.Server()
    enc_admindata = CtrBA.make_fake_admin(svr)
    @test CtrBA.is_admin(CtrBA.decrypt_userdata(svr, enc_admindata))
end

import ..Set4.CbcWithIvEqKey
@testset "cbc_iv_eq_key" begin
    svr = CbcWithIvEqKey.Server()
    recovered_key = CbcWithIvEqKey.recover_key_with_iv_eq_key(svr)
    @test svr.key == recovered_key
end

@testset "sha1_mac" begin
    # This challenge asks one to verify that you cannot tamper with the message without breaking the
    # MAC you've produced, and that you can't produce a new MAC without knowing the secret key.
    #
    # Manually verified.

    # An example from Wikipedia
    key = Vector{UInt8}("The quick brown fox")
    message = Vector{UInt8}(" jumps over the lazy dog")
    @test bytes2hex(sha1_mac(message, key)) == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
end

using CryptopalsCryptoChallenges.Set2.CbcBitflippingAttacks: is_admin
@testset "break_sha1_mac" begin
    key = Vector{UInt8}("The quick brown fox")
    sha1_mac_oracle(message::AbstractVector{UInt8}) = sha1_mac(message, key)
    (forged_message_no_key, forged_sha1) = forge_sha1(sha1_mac_oracle)

    @test is_admin(String(copy(forged_message_no_key))) &&
        sha1_mac(forged_message_no_key, key) == forged_sha1
end
