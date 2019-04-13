module CtrBitflippingAttacks

using Nettle: trim_padding_PKCS5

using CryptopalsCryptoChallenges.Set2: pkcs7_padding!
using CryptopalsCryptoChallenges.Set2.CbcBitflippingAttacks:
    add_comments,
    is_admin,
    PREFIX,
    POSTFIX,
    ADMIN_KV,
    ADMIN_PADDING_LEN
using CryptopalsCryptoChallenges.Set2.ByteAtATimeEcbDecryptionSimple: get_block
using CryptopalsCryptoChallenges.Set3: aes_128_ctr

export add_comments, is_admin, Server, encrypt_userdata, decrypt_userdata, make_fake_admin

struct Server
    key::Vector{UInt8}
    nonce::Int64

    Server() = new(rand(UInt8, 16), rand(Int64))  # a random pair of CTR key/nonce
end

function encrypt_userdata(svr::Server, userdata::String)::Vector{UInt8}
    bytes = add_comments(userdata)
    pkcs7_padding!(bytes, 16)
    aes_128_ctr(bytes, svr.key, svr.nonce)
end

function decrypt_userdata(svr::Server, userdata::Vector{UInt8})::String
    String(trim_padding_PKCS5(aes_128_ctr(userdata, svr.key, svr.nonce)))
end

#===== Cracker =====#
function make_fake_admin(svr::Server)::Vector{UInt8}
    prefix_padding_len = mod(-length(PREFIX), 16)
    fake_admin = String([UInt8(0) for _ in 1:(prefix_padding_len + 16)])
    n_prefix_blocks = (length(PREFIX) + prefix_padding_len) ÷ 16
    i_fake_admin_block = n_prefix_blocks + 1

    ADMIN_BLOCK = [ADMIN_KV; [UInt8('a') for _ in 1:ADMIN_PADDING_LEN]...]

    enc = encrypt_userdata(svr, fake_admin)
    fake_admin_block = get_block(enc, 16, i_fake_admin_block)  # reference returned
    fake_admin_block .⊻= ADMIN_BLOCK  # No need to apply another xor because we use `UInt8(0)`

    enc
end

end  # module
