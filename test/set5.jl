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
