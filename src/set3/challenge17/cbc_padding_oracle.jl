module CbcPaddingOracle

using Base64: base64decode
using Nettle: trim_padding_PKCS5

using CryptopalsCryptoChallenges.Set2: pkcs7_padding, aes_128_cbc_encode, aes_128_cbc_decode
using CryptopalsCryptoChallenges.Set2.ByteAtATimeEcbDecryptionSimple: get_block

struct Server
    # A consistent key is used throughout while a new IV is generated for each session.
    key::Vector{UInt8}

    Server() = new(rand(UInt8, 16))
end

# The first function
"Returns a pair of `(ciphertext, iv)`."
function encrypt_random(server::Server,
                        plaintext::Vector{UInt8})::Tuple{Vector{UInt8}, Vector{UInt8}}
    iv = rand(UInt8, 16)
    ciphertext = aes_128_cbc_encode(pkcs7_padding(plaintext, 16), server.key, iv)
    (ciphertext, iv)
end

function check_pkcs7(data::AbstractVector{UInt8})::Bool
    pad_len = data[end]
    0 < pad_len <= length(data) && all((@view data[end - pad_len + 1 : end]) .== pad_len)
end

# The second function
function check_padding(server::Server, ciphertext::AbstractVector{UInt8}, iv::Vector{UInt8})::Bool
    plaintext = aes_128_cbc_decode(ciphertext, server.key, iv)
    check_pkcs7(plaintext)
end

#===== Attacker =====#
function crack_a_block(server::Server,
                       cipher_block::AbstractVector{UInt8})::Vector{UInt8}
    @assert length(cipher_block) == 16
    cracked = Array{Union{Missing, UInt8}}(missing, 16)
    fake_iv = zeros(UInt8, 16)

    for b in 16:-1:1
        last_padding_code = UInt8(16 - b)
        curr_padding_code = last_padding_code + 0x01
        xor_padding_code = last_padding_code ⊻ curr_padding_code
        fake_iv[(b + 1):end] .⊻= xor_padding_code

        for i in 0x00:0xFF
            fake_iv[b] = i
            if check_padding(server, cipher_block, fake_iv)
                # For the first cracked byte (the last byte of the block), the decrypted bytes
                # probably ends with 0x01, but it is also possible that it ends with 0x0202.
                if b == 16
                    fake_iv[16 - 1] ⊻= 0xFF
                    if !check_padding(server, cipher_block, fake_iv)
                        continue
                    end
                end

                cracked[b] = curr_padding_code ⊻ fake_iv[b]
                break
            end
        end
    end

    @assert all(@. !ismissing(cracked))
    UInt8.(cracked)
end

function crack(server::Server, ciphertext::Vector{UInt8}, iv::Vector{UInt8})::Vector{UInt8}
    len = length(ciphertext)
    @assert len % 16 == 0
    plaintext = Array{UInt8}(undef, len)
    empty!(plaintext)
    n_blocks = len ÷ 16

    last_block = iv
    for b in 1:n_blocks
        cipher_block = get_block(ciphertext, 16, b)
        plain_block = crack_a_block(server, cipher_block)
        append!(plaintext, plain_block .⊻ last_block)
        last_block = cipher_block
    end

    trim_padding_PKCS5(plaintext)
end

end  # module
