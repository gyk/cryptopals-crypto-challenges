using Nettle: Encryptor, encrypt

export aes_128_ecb_encode, aes_128_cbc_decode, aes_128_cbc_encode

#====== Encoder =====#
function aes_128_ecb_encode(plaintext::AbstractVector{UInt8},
                            key::AbstractVector{UInt8})::Vector{UInt8}
    @assert length(plaintext) % 16 == 0 && length(key) == 16
    enc = Encryptor("AES128", key)
    encrypt(enc, plaintext)
end

function aes_128_cbc_encode(plaintext::AbstractVector{UInt8},
                            key::Vector{UInt8},
                            iv::Vector{UInt8}=zeros(UInt8, 16))::Vector{UInt8}
    @assert length(plaintext) % 16 == 0 && length(key) == 16
    enc = Array{UInt8}(undef, length(plaintext))
    empty!(enc)

    last_block = iv
    for b in Iterators.partition(plaintext, 16)
        enc_block = aes_128_ecb_encode(b .⊻ last_block, key)
        append!(enc, enc_block)
        last_block = enc_block
    end

    enc
end

#====== Decoder =====#
using CryptopalsCryptoChallenges.Set1: aes_128_ecb_decode

function aes_128_cbc_decode(ciphertext::AbstractVector{UInt8},
                            key::AbstractVector{UInt8},
                            iv::Vector{UInt8}=zeros(UInt8, 16))::Vector{UInt8}
    @assert length(ciphertext) % 16 == 0 && length(key) == 16
    dec = Array{UInt8}(undef, length(ciphertext))
    empty!(dec)

    last_block = iv
    for b in Iterators.partition(ciphertext, 16)
        dec_block = aes_128_ecb_decode(b, key) .⊻ last_block
        append!(dec, dec_block)
        last_block = b
    end

    dec
end

#====== Test =====#
using Nettle: decrypt
"A reference implementation of AES-128 CBC decoder."
function _aes_128_cbc_decode(ciphered::AbstractVector{UInt8},
                             key::AbstractVector{UInt8},
                             iv::Vector{UInt8}=zeros(UInt8, 16))::Vector{UInt8}
    @assert length(key) == 16
    decrypt("AES128", :CBC, iv, key, ciphered)
end
