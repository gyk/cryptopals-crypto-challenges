export RSAServer, encrypt_3_times_and_crack_message

# https://en.wikipedia.org/wiki/Nth_root_algorithm
"""
Comptes `n`-th root of `a` using Newton's method.

Precondition: `a` does be a `n`-th perfect power. If not, the returned value is not always the
closest approximation.
"""
function nth_root(a::T, n::T)::T where T<:Integer
    if iszero(a) || isone(a)
        return a
    end

    x = T(2)  # initial guess
    while true
        # Computes (a - x^n) / (n x^(n-1))
        xn1 = x ^ (n - 1)
        xn = xn1 * x

        delta = (a - xn) ÷ (n * xn1)
        if iszero(delta)
            return x + cmp(a, xn)
        end
        x += delta
    end
end

struct RSAServer
    message::Vector{UInt8}
end

#=
x = r_i  (mod n_i)
N = n_1 n_2 ... n_k
N_i = N / n_i

s_i N_i + t_i n_i = 1  =>
s_i = N_i ^ (-1)  (mod n_i)

x = sum(r_i s_i N_i)  (mod N)

(This is easy to see as $s_i N_i$ is congruent to 1 mod n_i and congruent to 0 mod n_j (j != i).)
=#

"Precondition: numbers in `n_list` are pairwise coprime"
function chinese_remainder_theorem(
    n_list::AbstractVector{T},
    r_list::AbstractVector{T},
)::T where T<:Integer
    N = prod(n_list)
    N_ = N .÷ n_list
    s_ = coprime_inv_mod.(N_, n_list)
    sum(r_list .* s_ .* N_) % N
end

function encrypt_3_times_and_crack_message(rsa_server::RSAServer)::Vector{UInt8}
    n_bits = 8 * length(rsa_server.message)
    n_list = BigInt[]
    r_list = BigInt[]
    for i in 1:3
        rsa = RSA(n_bits, big(3))
        (_, n) = rsa.public_key
        r = convert(BigInt, rsa_encrypt(rsa, rsa_server.message))
        push!(n_list, n)
        push!(r_list, r)
    end

    x3 = chinese_remainder_theorem(n_list, r_list)
    x = nth_root(x3, big(3))
    @assert x ^ big(3) == x3 "WTF $x^3 != $x3"
    convert(Vector{UInt8}, x)
end
