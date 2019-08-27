using SHA: sha1

using CryptopalsCryptoChallenges.Util: convert
using CryptopalsCryptoChallenges.Set6: DSA_P, DSA_Q, DSA_G

export
    DSASignedMessage,
    read_dsa_signed_msg_file,
    dsa_nonce_recover_from_repeated_nonce,
    dsa_private_key_from_nonce

struct DSASignedMessage
    msg::String
    s::BigInt
    r::BigInt
    h::Vector{UInt8}
end

function dsa_signed_msg_from_strings(params::Vector{String})::DSASignedMessage
    msg = String(match(r"(?:msg:\s*)(.*)", params[1]).captures[1])
    s = parse(BigInt,
        String(match(r"(?:s:\s*)(\d+)", params[2]).captures[1]))
    r = parse(BigInt,
        String(match(r"(?:r:\s*)(\d+)", params[3]).captures[1]))
    h = hex2bytes(
        String(match(r"(?:m:\s*)([0-9a-fA-F]+)", params[4]).captures[1]))
    DSASignedMessage(msg, s, r, h)
end

function read_dsa_signed_msg_file(filepath::String)::Vector{DSASignedMessage}
    lines = readlines(filepath)
    mapslices(dsa_signed_msg_from_strings, reshape(lines, 4, :), dims=[1])[:]
end

# k = ((H1 - H2) / (s1 - s2)) mod q
function dsa_nonce_recover_from_repeated_nonce(
    sig1::DSASignedMessage, sig2::DSASignedMessage,
)::BigInt
    h1 = convert(BigInt, sig1.h)
    h2 = convert(BigInt, sig2.h)
    s1 = sig1.s
    s2 = sig2.s
    (mod(h1 - h2, DSA_Q) * invmod(s1 - s2, DSA_Q)) % DSA_Q
end

function dsa_private_key_from_nonce(k::BigInt, sig::DSASignedMessage)::BigInt
    s = sig.s
    r = sig.r
    h = convert(BigInt, sig.h)
    (mod(s * k - h, DSA_Q) * invmod(r, DSA_Q)) % DSA_Q
end
