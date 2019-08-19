using CryptopalsCryptoChallenges.Util: convert
using CryptopalsCryptoChallenges.Set5: RSA, rsa_decrypt

export recover_unpadded_rsa

#=
C = (M ^ E) % N
C' = ((S^E % N) C) % N
M = (C ^ D) % N
P' = (C' ^ D) % N
   = (((S^E % N) C) ^ D) % N
   = ((S ^ (E D)) C ^ D) % N
   = (S M) % N
P = (P' / S) % N
=#

function recover_unpadded_rsa(rsa_oracle::RSA, cyphertext::Vector{UInt8})::Vector{UInt8}
    c = convert(BigInt, cyphertext)
    (e, n) = rsa_oracle.public_key

    s = (() -> while true
        s = rand(big(2):(n - 1))
        if gcd(s, n) == 1
            return s
        end
    end)()

    # Set 5's `coprime_inv_mod` also works
    inv_s = invmod(s, n)

    c_prime = (powermod(s, e, n) * c) % n
    p_prime = rsa_decrypt(rsa_oracle, c_prime)
    p = (p_prime * inv_s) % n
    convert(Vector{UInt8}, p)
end
