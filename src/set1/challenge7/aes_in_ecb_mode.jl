import Nettle: Decryptor, decrypt

export aes_128_ecb_decode

function aes_128_ecb_decode(ciphered::AbstractVector{UInt8},
                            key::AbstractVector{UInt8})::Vector{UInt8}
    @assert length(key) == 16
    dec = Decryptor("AES128", key)
    decrypt(dec, ciphered)
end
