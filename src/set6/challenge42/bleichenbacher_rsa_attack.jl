#=

Notes on Hal Finney's Writeup
=============================

Link: <https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE>

The 3072 bits case
------------------

The digest is formatted like this:

    00 01 FF FF FF ... FF 00  ASN.1  HASH

The forged digest taking advantage of a vulnerable implementation should be

    00 01 FF FF ... FF 00  ASN.1  HASH  GARBAGE

Let `D := [00  ASN.1  HASH]`, in the case of SHA-1, the length of D will be 36 bytes, or 288 bits.
And define `N := 2^288 - D`. Bleichenbacher chose to place the hash 2072 bits from the right. Hence
the `GARBAGE` length is 2072. And the `[00 01 FF FF ... FF 00 ... 00]` can be expressed numerically
as

    2 ^ (3072 - 8 - 7) - 2 ^ (288 + 2072) = 2 ^ 3057 - 2 ^ 2360

and the `D << 2072` part can be expressed as

    (2 ^ 288 - N) * (2 ^ 2072) = 2 ^ 2360 - N * (2 ^ 2072)

so the whole forged digest is

    2^3057 - N*2^2072 + GARBAGE

We just fit `(A-B)^3 = A^3 - 3(A^2)B + 3A(B^2) - B^3` with the last expression, that is,

    A^3 = (2^a)^3 = 2^(3 * a) == 2^3057  =>  a = 1019

    3(A^2)B = 3 (2^a)^2 (b * N) = 3 * 2^(2 * a) (b * N) == 2^2072 N  =>
    3 * 2^2038 (b * N) == 2^2072 N  =>
    3 b == 2^34  =>
    b = 2^34 / 3

and then we can derive that `GARBAGE` should be

    GARBAGE = 3A(B^2) - B^3
            = 3 (2 ^ 1019) (N * 2^34 / 3)^2 - (N * 2^34 / 3)^3

Obviously `N` must be a multiple of 3 ("which can easily be arranged by **slightly tweaking** the
message if neccessary.").

The 1024 bits case
------------------

In this challenge we don't have the freedom of "tweaking the message", so the "pencil and paper"
approach doesn't work. We have to find the cube root by computer.

=#

using SHA: sha1

using CryptopalsCryptoChallenges.Util: convert
using CryptopalsCryptoChallenges.Set5: RSA, rsa_encrypt, rsa_decrypt, nth_root

export bleichenbacher_rsa_attack

const RSA_BIT_LEN = 1024

function left_pad(data::Vector{UInt8}, len::Int)::Vector{UInt8}
    n_padding = len - length(data)
    if n_padding <= 0
        return data
    end
    vcat(zeros(UInt8, n_padding), data)
end

#=
ASN.1 value for SHA1 (Abstract Syntax Notation One, defined in X.208)

Defined in RFC 3447 (https://www.ietf.org/rfc/rfc3447.txt)

    SHA-1:   (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H.

    sha1    HashAlgorithm ::= {
        algorithm   id-sha1,
        parameters  SHA1Parameters : NULL
    }

References:

- https://stackoverflow.com/a/3715736
- http://luca.ntop.org/Teaching/Appunti/asn1.html
=#

const ASN1_SHA1 = [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
]

#=

    s = sha1(m) |> add_asn1 |> rsa_decrypt
    sha1(m) = s |> rsa_encrypt |> remove_asn1

Recall that `rsa_encrypt` is

    (s ^ e) % N

where `e` = 3. So `cbrt` is equivalent to `rsa_decrypt`, we can forge the signature with no access
to the private key:

    forged_s = sha1(m) |> add_asn1 |> cbrt
=#

function rsa_forge_signature(rsa::RSA, digest::Vector{UInt8})::Vector{UInt8}
    sig = vcat([0x00, 0x01, 0xFF, 0x00], ASN1_SHA1, digest)
    prefix_len = length(sig)
    n_padding = rsa.key_size ÷ 8 - length(sig)
    append!(sig, zeros(UInt8, n_padding))
    sig_int = convert(BigInt, sig)

    # Searches for an integer that produces a byte array with the same prefix as the signature.
    cbrt_sig_int = nth_root(sig_int, big(3))
    while true
        recovered_sig_int = cbrt_sig_int ^ 3
        recovered_sig = convert(Vector{UInt8}, recovered_sig_int)
        recovered_sig = left_pad(recovered_sig, rsa.key_size ÷ 8)

        if recovered_sig[1:prefix_len] == sig[1:prefix_len]
            @assert length(recovered_sig) == length(sig)
            return convert(Vector{UInt8}, cbrt_sig_int)
        elseif recovered_sig[1:prefix_len] < sig[1:prefix_len]
            cbrt_sig_int += 1
        else
            # This branch is unreachable because I have made `n_padding` sufficiently larger than
            # `prefix_len`. More specifically, if we can make sure that the inequation
            #
            #     b = 2 ^ ((3 + 36) * 8 - 8 - 6) = 298
            #     p = 1024 - (3 + 36) * 8 = 712
            #     (3 b^2 + 3 b + 1) < (2 ^ p)
            #
            #  always holds (which is true) then this will never happen.
            error("unreachable")
        end
    end
end

macro try_nothing(maybe)
    quote
        maybe = $(esc(maybe))
        if maybe == nothing
            return false
        else
            maybe
        end
    end
end

function read_byte(s::AbstractVector{UInt8})::Union{Nothing, Tuple{UInt8, SubArray{UInt8, 1}}}
    if isempty(s)
        return nothing
    end

    (s[1], @view s[2:end])
end

function rsa_verify_signature(rsa::RSA, message::Vector{UInt8}, sig::Vector{UInt8})::Bool
    sig = rsa_encrypt(rsa, sig)
    sig = left_pad(sig, rsa.key_size ÷ 8)
    s = sig

    (c, s) = @try_nothing(read_byte(s))
    if c != 0x00
        return false
    end

    (c, s) = @try_nothing(read_byte(s))
    if c != 0x01
        return false
    end

    (c, s) = @try_nothing(read_byte(s))
    if c != 0xFF  # Must have at least one (?)
        return false
    end

    while true
        (c, s) = @try_nothing(read_byte(s))
        if c == 0xFF
            continue
        elseif c == 0x00
            break
        else
            return false
        end
    end

    # Skips the step to extract digest length from ASN.1, just uses 20.

    if length(s) < length(ASN1_SHA1) + 20
        return false
    end
    s = @view s[(length(ASN1_SHA1) + 1):end]
    digest = s[1:20]

    digest == sha1(message)
end

function bleichenbacher_rsa_attack(message::Vector{UInt8})::Bool
    rsa = RSA(1024, big(3))
    digest = sha1(message)
    forged_sig = rsa_forge_signature(rsa, digest)
    rsa_verify_signature(rsa, message, forged_sig)
end
