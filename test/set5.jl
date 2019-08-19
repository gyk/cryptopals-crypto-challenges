using Test
using CryptopalsCryptoChallenges.Set5

@testset "diffie_hellman" begin
    dh1 = DiffieHellman()
    dh2 = DiffieHellman()

    secret1 = compute_secret(dh1, dh2.public_key)
    secret2 = compute_secret(dh2, dh1.public_key)

    @test secret1 == secret2
end

@testset "mitm_attack_on_dh" begin
    @test run_dh_normal()
    @test run_dh_mitm(ManInTheMiddle())
    @test run_dh_mitm(ManInTheMiddleGEq1())
    @test run_dh_mitm(ManInTheMiddleGEqP())
    @test run_dh_mitm(ManInTheMiddleGEqPMinus1())
end

using CryptopalsCryptoChallenges.Set5.SRP: run_srp
@testset "srp" begin
    @test run_srp()
end

using CryptopalsCryptoChallenges.Set5.SRPBad: run_srp_bad, run_srp_mitm
@testset "srp_bad" begin
    @test run_srp_bad()

    dict = readlines("assets/dict.txt")
    @test run_srp_mitm(dict)
end

using CryptopalsCryptoChallenges.Set5: RSA, rsa_encrypt, rsa_decrypt
@testset "rsa" begin
    rsa = RSA(10, big(3))

    m = big(42)
    c = rsa_encrypt(rsa, m)
    @test rsa_decrypt(rsa, c) == m

    m_bytes = Vector{UInt8}("Bill Clinton flew on Lolita Express at least 26 times.")
    rsa = RSA(8 * length(m_bytes))
    c_bytes = rsa_encrypt(rsa, m_bytes)
    @test rsa_decrypt(rsa, c_bytes) == m_bytes
end

using CryptopalsCryptoChallenges.Set5: RSAServer, encrypt_3_times_and_crack_message
@testset "rsa_broadcast_attack" begin
    secret = Vector{UInt8}("Colin Powell: Bill Clinton is still #DickingBimbos")
    rsa_server = RSAServer(secret)
    cracked_secret = encrypt_3_times_and_crack_message(rsa_server)
    @test cracked_secret == secret
end
