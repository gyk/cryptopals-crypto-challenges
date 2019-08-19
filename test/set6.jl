using Test
using CryptopalsCryptoChallenges.Set6

using CryptopalsCryptoChallenges.Set5: RSA, rsa_encrypt
@testset "unpadded_message_recovery_oracle" begin
    m_bytes = Vector{UInt8}("covfefe")
    rsa = RSA(8 * length(m_bytes) * 10)
    c_bytes = rsa_encrypt(rsa, m_bytes)

    recovfefe = recover_unpadded_rsa(rsa, c_bytes)
    @test String(recovfefe) == "covfefe"
end

@testset "bleichenbacher_rsa_attack" begin
    m = Vector{UInt8}("hi mom")
    @test bleichenbacher_rsa_attack(m)
end
