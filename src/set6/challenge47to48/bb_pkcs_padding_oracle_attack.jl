"""
# Bleichenbacher's PKCS#1 v1.5 Padding Oracle Attack.

Challenge 47 asks you to implement a simplified attack first. It is skipped. Only the complete case
(Challenge 48) is done here.

## References

Besides Bleichenbacher's original paper, I find Gage Boyle's technical report "20 years of
Bleichenbacher attacks" helps tremendously.
"""

using CryptopalsCryptoChallenges.Util: convert
using CryptopalsCryptoChallenges.Set5: RSA

export bb_padding_oracle_attack, check_pkcs1_conforming, pkcs1_pad

@inline function check_encryption_block(eb::AbstractVector{UInt8}, rsa::RSA)::Bool
    (_, n) = rsa.public_key
    if eb[1] == 0x00
        println("WTH, the 1st byte of EB is 0x00")
        eb = @view eb[2:end]
    end
    k = ndigits(n, base=256)

    length(eb) == k - 1 && eb[1] == 0x02 && all((@view eb[2:9]) .!== 0x00)
end

function check_pkcs1_conforming(rsa::RSA, c_bytes::AbstractVector{UInt8})::Bool
    eb = rsa_decrypt(rsa, c_bytes)
    check_encryption_block(eb, rsa)
end

function check_pkcs1_conforming(rsa::RSA, c::BigInt)::Bool
    eb = convert(Vector{UInt8}, rsa_decrypt(rsa, c))
    check_encryption_block(eb, rsa)
end

# The PKCS 1.5 Padding:
#
#     m = [0x00 0x02 || PS || 0x00 || D]
#
#     k = |m|  (byte length of RSA n parameter)
#     |PS| = k - 3 - |D| >= 8
#     |D| <= k - 11
#

"Applies PKCS#1 v1.5 padding."
function pkcs1_pad(data::AbstractVector{UInt8}, n::BigInt)::Vector{UInt8}
    k = ndigits(n, base=256)
    if length(data) > k - 11
        error("Message too long")
    end
    padding_str = rand(0x01:0xFF, k - 3 - length(data))
    [0x00, 0x02, padding_str..., 0x00, data...]
end

function pkcs1_unpad(padded_data::AbstractVector{UInt8}, n::BigInt)::Vector{UInt8}
    k = ndigits(n, base=256)
    if length(padded_data) > k
        error("Padded data too long")
    end

    if padded_data[1] == 0x00
        println("WTH, the 1st byte of padded data is 0x00")
        padded_data = @view padded_data[2:end]
    end

    for i in 10:length(padded_data)
        if padded_data[i] == 0x00
            return padded_data[i + 1:end]
        end
    end
    error("Invalid padded data")
end

## Boundaries are tricky to get right.

# Another implementation for `divGtEq` is
#
#     (x + y - 1) ÷ y
#
# and another implementation for `divLt` is
#
#     (x + y - 1) ÷ y - 1
#
# but benchmarks show the `divrem` approaches are slightly faster.
# Also note that the behavior of `÷` in Julia is different from `//` in Python.

# x / y ⩽ z, or z = ⌈x / y⌉...
@inline function divGtEq(x::BigInt, y::BigInt)::BigInt
    (q, r) = divrem(x, y)
    if r == 0
        q
    else
        q + 1
    end
end

# z ⩽ x / y, or z = ...⌊x / y⌋
@inline function divLtEq(x::BigInt, y::BigInt)::BigInt
    x ÷ y
end

# x / y < z
@inline function divGt(x::BigInt, y::BigInt)::BigInt
    x ÷ y + 1
end

# z < x / y
@inline function divLt(x::BigInt, y::BigInt)::BigInt
    (q, r) = divrem(x, y)
    if r == 0
        q - 1
    else
        q
    end
end

"""
Precondition: `ciphertext` is already PKCS conforming so Step 1 is skipped, s_0 = 1 and m_0 = m.
"""
function bb_padding_oracle_attack(
    ciphertext::AbstractVector{UInt8},
    rsa_public_key::Tuple{BigInt, BigInt},
    padding_oracle::Function,
)::Vector{UInt8}
    c = convert(BigInt, ciphertext)
    @assert padding_oracle(c)

    (e, n) = rsa_public_key
    k = ndigits(n, base=256)
    B = big(1) << (8 * (k - 2))

    # The intervals
    M_i = [(2B, 3B - 1)]

    # Searches in the range `[from, to]` for `s_i`.
    function search_s(from::BigInt, to::BigInt)::Union{Nothing, BigInt}
        for s in from:to
            if padding_oracle((c * powermod(s, e, n)) % n)
                return s
            end
        end
        nothing
    end

    function check_s(maybe_s::Union{Nothing, BigInt})::BigInt
        if isnothing(maybe_s)
            error("Cannot find `s_i`")
        else
            maybe_s
        end
    end

    i = big(1)

    # [Step 2.a]: Finds the smallest `s_1` that `(c_0 (s_1 ^ e)) mod n` is PKCS conforming.
    #
    # Here is the derivation of `s_1 >= n / (3B)`. We already have `m < 3B`, and the following
    # inequation must hold:
    #
    #     m * s_1 > n
    #
    # Otherwise, the modular operation is not applied, so the 2 MSBs of `m * s` cannot be
    # 0x00_02. Therefore we get (note that it's a '>' instead of '>=', but this doesn't compromise
    # the correctness)
    #
    #     s_1 > n / m > n / 3B
    #
    s_i = search_s(divGtEq(n, 3B), n - 1) |> check_s
    while true
        # [Step 2]: Finds `s_i`.
        if length(M_i) > 1
            # [Step 2.b]: Searching with more than one interval left.
            #
            # Searches for `s_i` in a brute-force fashion. No better ways to optimize.
            s_i = search_s(s_i + 1, n - 1) |> check_s
        elseif M_i[1][1] == M_i[1][2]
            # [Step 4]: Computing the solution, when `M_i = {[a, a]}`.
            m = M_i[1][1]
            plaintext = convert(Vector{UInt8}, m)
            return pkcs1_unpad(plaintext, n)
        else
            # [Step 2.c]: Searching for the smallest `s_i` (i > 1), with one interval left.
            #
            # According to Gage Boyle's technical report, Eq. (1) in Bleichenbacher's original paper
            # is incorrect. It should be
            #
            #     r_i >= 2 * (b s_{i - 1} - B) / n
            #
            # The technique used in the paper is to speed up the narrowing of the intervals by
            # dividing the interval size roughly in half at each iteration. As `s_i` is the
            # denominator, we expect `s_i >= s_{i - 1} * 2`. Similar to Step 3, we have
            #
            #     2B <= m s_i - r_i n  ⟹  (∃ m, not ∀ m)
            #     2B + r_i n <= b s_i  ⟹
            #     (2B + r_i n) / b <= s_i  ⟹  (s_i >= 2 s_{i - 1})
            #     2 s_{i - 1} <= (2B + r_i n) / b  ⟹
            #     r_i >= 2 (b s_{i - 1} - B) / n
            #
            (a, b) = M_i[1]
            # NOTE: It's `s_{i - 1}` so `s_1` has to be specially handled.
            s_i_last = i == 1 ? 1 : s_i
            r_i = divGtEq(big(2) * (b * s_i_last - B), n)
            s_i = nothing
            while isnothing(s_i)
                s_i = search_s(
                    divGtEq(2B + r_i * n, b),
                    divLt(3B + r_i * n, a),
                )
                r_i += 1
            end
        end

        # [Step 3]: Narrowing the set of solutions `M_i` after `s_i` has been found.
        #
        # Derivation of the interval of `r`. We have already found `s_i` s.t. `(m s_i) mod n` is
        # PKCS conforming, and `m ∈ [a, b]`. So
        #
        #     2B <= m s_i - r_i n < 3B  ⟹
        #     m s_i - 3B < r_i n <= m s_i - 2B  ⟹
        #     (a s_i - 3B) / n < r_i <= (b s_i - 2B) / n
        #
        new_M_i = Tuple{BigInt, BigInt}[]
        for (a, b) in M_i
            for r_i in divGtEq(a * s_i - 3B + 1, n):divLtEq(b * s_i - 2B, n)
                new_a = max(a, divGtEq(2B + r_i * n, s_i))
                new_b = min(b, divLtEq(3B - 1 + r_i * n, s_i))
                if new_a <= new_b  # If it's a valid interval
                    push!(new_M_i, (new_a, new_b))
                end
            end
        end
        M_i = unify_intervals!(new_M_i)

        i += 1
    end
end

function unify_intervals!(intervals::Vector{Tuple{BigInt, BigInt}})::Vector{Tuple{BigInt, BigInt}}
    sort!(intervals)
    ret = [intervals[1]]
    for (l, u) in @view intervals[2:end]
        if l <= ret[end][2]
            if u > ret[end][2]
                ret[end] = (ret[end][1], u)
            end
        else
            push!(ret, (l, u))
        end
    end
    ret
end
