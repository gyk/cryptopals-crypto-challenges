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

using SHA: sha1
using CryptopalsCryptoChallenges.Util: convert
@testset "dsa_key_recover_from_nonce" begin
    MESSAGE = Vector{UInt8}("""
        For those that envy a MC it can be hazardous to your health
        So be friendly, a matter of life and death, just like a etch-a-sketch
        """)  # ends with newline

    # public key
    Y = parse(BigInt,
        """0x
        84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
        abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
        e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
        1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
        bb283e6633451e535c45513b2d33c99ea17""")

    R = big(548099063082341131477253921760299949438196259240)
    S = big(857042759984254168557880549501802188789837994940)
    x = recover_dsa_key_nonce(MESSAGE, (R, S), Y)

    # Converts private key to hex string. Byte array doesn't work.
    @test sha1(string(x, base=16)) == hex2bytes("0954edd5e0afe5542a4adf012611a91912a3ec16")

    # Tests DSA
    dsa = begin
        dsa = default_dsa()
        DSA(dsa.p, dsa.q, dsa.g, x, Y)
    end

    sig = sign_dsa(dsa, MESSAGE)
    @test verify_dsa(dsa, MESSAGE, sig)
end
