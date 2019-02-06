module EcbCutAndPaste

using CryptopalsCryptoChallenges.Set1: aes_128_ecb_decode
using ..Set2

# NOTE: Nettle's `trim_padding_PKCS5` is indeed a loose implementation that neither checks the
# padded bytes nor padding length. As a result it can also be used for PKCS#7.
import Nettle: trim_padding_PKCS5

export Admin, is_admin, profile_for, encrypt_user_profile, decrypt_user_profile, lift_to_admin

function parse_kv(uri_params)::Dict
    Dict(
        begin
            (k, v) = split(kv, "=")
            k => v
        end
        for kv in split(uri_params, "&")
    )
end

function is_admin(profile_kv::String)::Bool
    parse_kv(profile_kv)["role"] == "admin"
end

function profile_for(email::String)
    email = replace(email, r"[=&]" => "")
    "email=$email&uid=10&role=user"
end

struct Admin
    key::Vector{UInt8}

    Admin() = new(rand(UInt8, 16))  # a very random AES key
end

"""
Encrypts user profile encoded as URI parameter using AES-128 ECB mode.

- Input: encoded string of user profile, e.g., "email=foo@bar.com&uid=10&role=user"
- Output: AES-128 encrypted byte vector
"""
function encrypt_user_profile(admin::Admin, user_profile::String)::Vector{UInt8}
    bytes = Vector{UInt8}(user_profile)
    pkcs7_padding!(bytes, 16)
    aes_128_ecb_encode(bytes, admin.key)
end

"The reverse of `encrypt_user_profile`."
function decrypt_user_profile(admin::Admin, user_profile::Vector{UInt8})::String
    String(trim_padding_PKCS5(aes_128_ecb_decode(user_profile, admin.key)))
end

function encrypted_profile_for(admin::Admin, email::String)::Vector{UInt8}
    user_profile = profile_for(email)
    encrypt_user_profile(admin, user_profile)
end

#===== Cracker =====#
function lift_to_admin(enc_user_profile::Vector{UInt8}, profile_oracle::Admin)::Vector{UInt8}
    # For simplicity, assumes the attacker has already known the block size is 16.
    ADMIN = b"admin"
    USER = b"user"
    EMAIL_PREFIX = b"email="
    n_padding1 = 16 - length(EMAIL_PREFIX)
    n_padding2 = 16 - length(ADMIN)
    padding1 = [UInt8(n_padding1) for _ in 1:n_padding1]
    padding2 = [UInt8(n_padding2) for _ in 1:n_padding2]
    # EMAIL_PREFIX is prepended by `profile_for` function
    probe = String([padding1; ADMIN; padding2])
    admin_block = encrypted_profile_for(profile_oracle, probe)[16 + 1 : 32]

    probe_email_len = mod(-(length(profile_for("")) - length(USER)), 16)
    probe_email = String([UInt8('a') for _ in 1:probe_email_len])
    partial_block = encrypted_profile_for(profile_oracle, probe_email)
    [partial_block[1:32]; admin_block]
end

end  # module
