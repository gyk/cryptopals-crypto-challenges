module CbcWithIvEqKey

using CryptopalsCryptoChallenges.Set2: pkcs7_padding!
using CryptopalsCryptoChallenges.Set2: aes_128_cbc_encode, aes_128_cbc_decode
using CryptopalsCryptoChallenges.Set2.ByteAtATimeEcbDecryptionSimple: get_block

# NOTE: The description links to Challenge 16 but actually we can base our implementation on
# Challenge 10?

URL_STRING = begin
    url = "Facebook stores users' passwords in plain text"  # not really a URL
    url_len = length(url)
    padding_len = if url_len < 16 * 3
        16 * 3 - url_len
    else
        mod(-length(url), 16)
    end

    url * repeat(' ', padding_len)
end

#===== The Server =====#
struct Server
    key::Vector{UInt8}
    iv::Vector{UInt8}

    function Server()
        key_doubled_as_iv = rand(UInt8, 16)
        new(key_doubled_as_iv, key_doubled_as_iv)
    end
end

function encrypt_userdata(svr::Server, userdata::String)::Vector{UInt8}
    bytes = Vector{UInt8}(userdata)
    pkcs7_padding!(bytes, 16)
    aes_128_cbc_encode(bytes, svr.key, svr.iv)
end

function decrypt_userdata_keep_padding(svr::Server, userdata::Vector{UInt8})::String
    # Nettle's `trim_padding_PKCS5` does not check padding length
    String(aes_128_cbc_decode(userdata, svr.key, svr.iv))
end

function check_url(svr::Server, encrypted_url::Vector{UInt8})::Union{Nothing, String}
    url = decrypt_userdata_keep_padding(svr, encrypted_url)
    if isascii(url)
        nothing
    else
        url
    end
end

#=
How it works:

    P1 = aes(C1, key) ^ iv
    P2 = aes(C2, key) ^ C1
    P3 = aes(C3, key) ^ C2

When iv = key, C3 = C1, C2 = 0, it is deduced to

    P1 = aes(C1, key) ^ key
    P2 = aes(0, key) ^ C1
    P3 = aes(C1, key) ^ 0

In other words, P1 ^ P3 == key.
=#

function recover_key_with_iv_eq_key(svr::Server)::Vector{UInt8}
    encrypted_url = encrypt_userdata(svr, URL_STRING)
    get_block(encrypted_url, 16, 2) .= UInt8(0)
    get_block(encrypted_url, 16, 3) .= get_block(encrypted_url, 16, 1)

    check_result = check_url(svr, encrypted_url)
    if check_result === nothing
        error("Checking ASCII compliance passed. WTF?")
    end

    dec = Vector{UInt8}(check_result)
    get_block(dec, 16, 1) .⊻ get_block(dec, 16, 3)
end

end  # module
