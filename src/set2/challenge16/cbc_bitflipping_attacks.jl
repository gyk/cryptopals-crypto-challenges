module CbcBitflippingAttacks

using ..Set2
using ..ByteAtATimeEcbDecryptionSimple: get_block

# NOTE: Nettle's `trim_padding_PKCS5` is indeed a loose implementation that neither checks the
# padded bytes nor padding length. As a result it can also be used for PKCS#7.
import Nettle: trim_padding_PKCS5

export add_comments, is_admin, Admin, encrypt_userdata, decrypt_userdata, make_fake_admin

# Assumes these are already known to the cracker
const PREFIX = b"comment1=cooking%20MCs;userdata="
const POSTFIX = b";comment2=%20like%20a%20pound%20of%20bacon"

const ADMIN_KV = b";admin=true;"
const ADMIN_PADDING_LEN = 16 - length(ADMIN_KV)  # Uh...

function add_comments(userdata::String)::Vector{UInt8}
    [
        PREFIX;
        userdata |> s -> replace(s, "=" => "%3D") |> s -> replace(s, ";" => "%3B") |> Vector{UInt8};
        POSTFIX;
    ]
end

function parse_kv(uri_params)::Dict
    d = Dict()
    for kv in split(uri_params, ";")
        kv = split(kv, "=")
        if length(kv) != 2
            continue
        end
        (k, v) = kv
        d[k] = v
    end
    d
end

function is_admin(profile_kv::String)::Bool
    kv = parse_kv(profile_kv)
    haskey(kv, "admin") && kv["admin"] == "true"
end

struct Admin
    key::Vector{UInt8}
    iv::Vector{UInt8}

    Admin() = new(rand(UInt8, 16), rand(UInt8, 16))  # a very random pair of AES key/IV
end

function encrypt_userdata(admin::Admin, userdata::String)::Vector{UInt8}
    bytes = add_comments(userdata)
    pkcs7_padding!(bytes, 16)
    aes_128_cbc_encode(bytes, admin.key, admin.iv)  # FIXME: IV?
end

function decrypt_userdata(admin::Admin, userdata::Vector{UInt8})::String
    String(trim_padding_PKCS5(aes_128_cbc_decode(userdata, admin.key, admin.iv)))
end

#===== Cracker =====#
function make_fake_admin(admin::Admin)::Vector{UInt8}
    prefix_padding_len = mod(-length(PREFIX), 16)
    fake_admin = String([UInt8('a') for _ in 1:(prefix_padding_len + 16 * 2)])
    n_prefix_blocks = (length(PREFIX) + prefix_padding_len) ÷ 16
    i_bitflipping_block = n_prefix_blocks + 1
    i_fake_admin_block = i_bitflipping_block + 1

    ADMIN_BLOCK = [ADMIN_KV; [UInt8('a') for _ in 1:ADMIN_PADDING_LEN]...]

    enc = encrypt_userdata(admin, fake_admin)
    dec = decrypt_userdata(admin, enc)
    dec = Vector{UInt8}(dec)

    bitflipping = get_block(dec, 16, i_fake_admin_block) .⊻ ADMIN_BLOCK
    bitflipping_block = get_block(enc, 16, i_bitflipping_block)  # reference returned
    bitflipping_block .⊻= bitflipping

    enc
end

end  # module
