using Nettle: Encryptor, encrypt

export aes_128_ecb_encode, aes_128_cbc_decode, aes_128_cbc_encode

#====== Encoder =====#
function aes_128_ecb_encode(plaintext::AbstractVector{UInt8},
                            key::AbstractVector{UInt8})::Vector{UInt8}
    @assert length(key) == 16
    enc = Encryptor("AES128", key)
    encrypt(enc, plaintext)
end

function aes_128_cbc_encode(plaintext::AbstractVector{UInt8},
                            key::Vector{UInt8},
                            iv::Vector{UInt8}=zeros(UInt8, 16))::Vector{UInt8}
    len_text = length(plaintext)
    ret = Array{UInt8}(undef, len_text + mod(-len_text, 16))
    empty!(ret)

    cur_block = iv
    for b in Iterators.partition(plaintext, 16)
        for (i, ch) in enumerate(b)
            cur_block[i] ⊻= ch
        end
        enc_block = aes_128_ecb_encode(cur_block, key)
        append!(ret, enc_block)
        cur_block = enc_block
    end

    ret
end

#====== Decoder =====#
using CryptopalsCryptoChallenges.Set1: aes_128_ecb_decode

function aes_128_cbc_decode(cipherbytes::AbstractVector{UInt8},
                            key::AbstractVector{UInt8})::Vector{UInt8}
    ret = Array{UInt8}(undef, length(cipherbytes))
    empty!(ret)

    iv = zeros(UInt8, 16)
    last_block = iv
    for b in Iterators.partition(cipherbytes, 16)
        dec_block = aes_128_ecb_decode(b, key)
        for (i, ch) in enumerate(last_block)
            dec_block[i] ⊻= ch
        end
        append!(ret, dec_block)
        last_block = b
    end

    ret
end

#====== Test =====#
using Nettle: decrypt
"A reference implementation of AES-128 CBC decoder."
function _aes_128_cbc_decode(ciphered::AbstractVector{UInt8},
                             key::AbstractVector{UInt8})::Vector{UInt8}
    @assert length(key) == 16
    decrypt("AES128", :CBC, zeros(UInt8, 16), key, ciphered)
end
