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
