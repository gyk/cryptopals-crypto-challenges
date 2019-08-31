using CryptopalsCryptoChallenges.Util: convert
using CryptopalsCryptoChallenges.Set5: RSA

export make_rsa_parity_oracle, recover_rsa_message

"""
Is the plaintext of this message even or odd? (Or, is the last bit of the message 0 or 1?)

# Return value of the returned HOF

- `true`: odd
- `false`: even
"""
function make_rsa_parity_oracle(rsa::RSA)::Function
    function rsa_parity_oracle(c::BigInt)
        isodd(rsa_decrypt(rsa, c))
    end

    rsa_parity_oracle
end

#=
Doubling the ciphertext to probe the value of plaintext:

    c = (m ^ e) % n
    m' = (2^e c)^d % n
       = (2^(e d) m^(e d)) % n
       = 2 m

If the plaintext `p` of `c` is odd, it wraps the modulus, and it is less than the modulus times 2.
=#

#--------------------------------#

#=

match `(2 p) % n`
- even  =>
    - p < n / 2
    - p' = 2 p
- odd =>
    - p > n / 2
    - p' = 2 p - n

Depending on the parity returned from the oracle, we alternately get `2 p` or `2 p - n` in the
iteration. For example, we might get something like

    2 (2 2 (2 p - n) - n) - n

Denote it as `poly(p, n)`. Initially, we have lower bound `l = 0`, upper bound `u = n`, both
exclusive. And note that the initial parity is even (E) because `p < n`. Now derive the transition
at each iteration:

The first example, the E-E transition:

    (E) => poly(p, n) < n / 2
    (E) => poly(p, n) * 2 > n / 2

so that

    x < u  =>  x < u - n / (2 ^ (k - 1)) + n / (2 ^ k)

We can write down all of the 4 transitions at iteration `k`:

    x < u  --[E,E]-->  x < u - n / (2 ^ (k - 1)) + n / (2 ^ k)
    x < u  --[E,O]-->  x > u - n / (2 ^ (k - 1)) + n / (2 ^ k)
    x > l  --[O,E]-->  x < l + n / (2 ^ k)
    x > l  --[O,O]-->  x > l + n / (2 ^ k)

It is easy to see that the length of the interval after step `k` is `n / (2 ^ k)`, so the above
transition can also be written as

    delta := (u - l) / 2
    x < u  --[E,E]-->  x < u - delta
    x < u  --[E,O]-->  x > u - delta
    x > l  --[O,E]-->  x < l + delta
    x > l  --[O,O]-->  x > l + delta

The interval progressively shrinks to the first (E) or second (O) half sub-interval of the current
one:

    `O E O` => `1 0 1` => (101)_2 = (5)_10, 0-based
            => the 6-th interval of `1/8 n`, namely, `(5/8, 6/8)`
=#

function recover_rsa_message(
    ciphertext::Vector{UInt8},
    parity_oracle::Function,
    public_key::Tuple{BigInt, BigInt},
)::Vector{UInt8}
    c = convert(BigInt, ciphertext)
    (e, n) = public_key
    two_enc = powermod(2, e, n)

    setprecision(BigFloat, ndigits(n, base=2) * 2) do
        lower = BigFloat(0)  # exclusively
        upper = BigFloat(n)  # exclusively
        while upper - lower >= 1.0
            c *= two_enc
            delta = (upper - lower) / 2

            if parity_oracle(c)
                c -= n  # saves some memory
                lower += delta
            else
                upper -= delta
            end
        end
        m = BigInt(round((lower + upper) / 2))
        convert(Vector{UInt8}, m)
    end
end
