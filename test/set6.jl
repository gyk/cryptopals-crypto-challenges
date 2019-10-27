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

    sig = dsa_sign(dsa, MESSAGE)
    @test dsa_verify(dsa, MESSAGE, sig)
end

using SHA: sha1
@testset "dsa_nonce_recover_from_repeated_nonce" begin
    sigs = read_dsa_signed_msg_file("assets/challenge44.txt")
    x = nothing

    r_to_sig_dict = Dict()
    for s in sigs
        if haskey(r_to_sig_dict, s.r)
            sig1 = r_to_sig_dict[s.r]
            sig2 = s
            k = dsa_nonce_recover_from_repeated_nonce(sig1, sig2)
            x = dsa_private_key_from_nonce(k, sig1)
            break
        else
            r_to_sig_dict[s.r] = s
        end
    end

    if x === nothing
        error("Cannot recover DSA nonce")
    end
    @test sha1(string(x, base=16)) == hex2bytes("ca8f6f7c66fa362d40760d135b763eb8527d3d52")
end

@testset "dsa_parameter_tampering" begin
    hello = Vector{UInt8}("Hello, world")
    goodbye = Vector{UInt8}("Goodbye, world")

    dsa = default_dsa() |> dsa_tamper_param_g_eq_0
    sig0 = dsa_sign_g_eq_0(dsa, hello)
    @test dsa_verify_g_eq_0(dsa, hello, sig0)
    @test dsa_verify_g_eq_0(dsa, goodbye, sig0)

    dsa = default_dsa() |> dsa_tamper_param_g_eq_p_plus_1
    sig1 = dsa_sign(dsa, hello)
    @test dsa_verify(dsa, goodbye, sig1)
end

using Base64: base64decode
using CryptopalsCryptoChallenges.Set5: RSA, rsa_encrypt
@testset "rsa_parity_oracle" begin
    plaintext_base64 = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
    plaintext = base64decode(plaintext_base64)

    rsa = RSA(1024)
    ciphertext = rsa_encrypt(rsa, plaintext)
    rsa_oracle = make_rsa_parity_oracle(rsa)
    plaintext_recovered = recover_rsa_message(ciphertext, rsa_oracle, rsa.public_key)
    @test plaintext_recovered == plaintext
end

using CryptopalsCryptoChallenges.Set5: RSA, rsa_encrypt
@testset "bleichenbacher_pkcs_padding_oracle" begin
    plaintext = Vector{UInt8}("kick it, CC")
    rsa = RSA(768)
    (_, n) = rsa.public_key
    ciphertext = rsa_encrypt(rsa, pkcs1_pad(plaintext, n))

    function padding_oracle(c::BigInt)::Bool
        check_pkcs1_conforming(rsa, c)
    end

    @test plaintext == bb_padding_oracle_attack(ciphertext, rsa.public_key, padding_oracle)
end
