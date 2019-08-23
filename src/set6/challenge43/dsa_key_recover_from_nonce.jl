using SHA: sha1

using CryptopalsCryptoChallenges.Util: convert

export DSA, default_dsa, sign_dsa, verify_dsa, recover_dsa_key_nonce

const DSA_P = parse(BigInt,
    """0x
    800000000000000089e1855218a0e7dac38136ffafa72eda7
    859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
    2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
    ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
    b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
    1a584471bb1
    """)

const DSA_Q = parse(BigInt, "0xf4f47f05794b256174bba6e9b396a7707e563c5b")

const DSA_G = parse(BigInt,
    """0x
    5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
    458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
    322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
    0f5b64c36b625a097f1651fe775323556fe00b3608c887892
    878480e99041be601a62166ca6894bdd41a7054ec89f756ba
    9fc95302291
    """)


struct DSA
    p::BigInt
    q::BigInt
    g::BigInt

    "The private key"
    x::BigInt
    "The public key"
    y::BigInt
end

function default_dsa()::DSA
    p = DSA_P
    q = DSA_Q
    g = DSA_G
    x = rand(big(1):(DSA_Q - big(1)))
    y = powermod(g, x, p)

    DSA(p, q, g, x, y)
end

function sign_dsa(dsa::DSA, message::Vector{UInt8})::Tuple{BigInt, BigInt}
    p, q, g, x = dsa.p, dsa.q, dsa.g, dsa.x
    digest = sha1(message)
    h = convert(BigInt, digest)

    # `r` and `k^(-1)` can be computed before the message is known.

    r = big(0)
    s = big(0)
    while s == 0
        k = rand(big(1):(DSA_Q - big(1)))  # nonce
        while r == 0
            r = powermod(dsa.g, k, p) % q
        end

        t = (h + x * r) % q
        s = (invmod(k, q) * t) % q
    end

    (r, s)
end

function verify_dsa(dsa::DSA, message::Vector{UInt8}, signature::Tuple{BigInt, BigInt})::Bool
    (r, s) = signature
    p, q, g, y = dsa.p, dsa.q, dsa.g, dsa.y
    digest = sha1(message)
    h = convert(BigInt, digest)

    if !(0 < r < q && 0 < s < q)
        return false
    end

    w = invmod(s, q)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v = ((powermod(g, u1, p) * powermod(y, u2, p)) % p) % q  # `% p` is important

    v == r
end

function recover_dsa_key_nonce(
    message::Vector{UInt8},
    signature::Tuple{BigInt, BigInt},
    y::BigInt,
    p::BigInt = DSA_P,
    q::BigInt = DSA_Q,
    g::BigInt = DSA_G,
)::BigInt
    (r, s) = signature
    digest = sha1(message)
    h = convert(BigInt, digest)

    for k in 1:(2 ^ 16)
        if powermod(g, k, p) % q == r
            return (mod(s * k - h, q) * invmod(r, q)) % q
        end
    end

    error("Unable to recover DSA private key")
end
