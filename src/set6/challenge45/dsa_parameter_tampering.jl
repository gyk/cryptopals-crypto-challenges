using CryptopalsCryptoChallenges.Set6: DSA

export
    dsa_tamper_param_g_eq_0,
    dsa_sign_g_eq_0,
    dsa_verify_g_eq_0,
    dsa_tamper_param_g_eq_p_plus_1

# y = (g ^ x) % p

function dsa_tamper_param_g_eq_0(dsa::DSA)::DSA
    p = dsa.p
    q = dsa.q
    g = big(0)
    x = dsa.x
    y = big(0)

    DSA(p, q, g, x, y)
end

function dsa_sign_g_eq_0(dsa::DSA, message::Vector{UInt8})::Tuple{BigInt, BigInt}
    p, q, g, x = dsa.p, dsa.q, dsa.g, dsa.x
    digest = sha1(message)
    h = convert(BigInt, digest)

    k = rand(big(1):(DSA_Q - big(1)))
    r = big(0)
    t = (h + x * r) % q
    s = (invmod(k, q) * t) % q

    (r, s)
end

# The same as `dsa_verify` but does not check the condition `0 < r < q && 0 < s < q`.
function dsa_verify_g_eq_0(dsa::DSA, message::Vector{UInt8}, signature::Tuple{BigInt, BigInt})::Bool
    (r, s) = signature
    p, q, g, y = dsa.p, dsa.q, dsa.g, dsa.y
    digest = sha1(message)
    h = convert(BigInt, digest)

    w = invmod(s, q)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v = ((powermod(g, u1, p) * powermod(y, u2, p)) % p) % q  # `% p` is important

    v == r
end

function dsa_tamper_param_g_eq_p_plus_1(dsa::DSA)::DSA
    p = dsa.p
    q = dsa.q
    g = dsa.p + 1
    x = dsa.x
    y = big(1)

    DSA(p, q, g, x, y)
end
