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
