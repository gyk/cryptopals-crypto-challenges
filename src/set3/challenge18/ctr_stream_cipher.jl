using CryptopalsCryptoChallenges.Set2: aes_128_ecb_encode

export aes_128_ctr

# `data` can either be plaintext or ciphertext.
function aes_128_ctr(data::AbstractVector{UInt8},
                     key::AbstractVector{UInt8},
                     nonce::Int64,
                     counter::UInt64=UInt64(0))::Vector{UInt8}
    @assert length(key) == 16
    # It is named `ciphertext` but actually should be plaintext in decryption mode.
    ciphertext = Array{UInt8}(undef, length(data))
    empty!(ciphertext)
    nonce_bytes = reinterpret(UInt8, [htol(nonce)])

    for b in Iterators.partition(data, 16)
        counter_bytes = reinterpret(UInt8, [htol(counter)])
        ctr_block = [nonce_bytes; counter_bytes]
        key_block = aes_128_ecb_encode(ctr_block, key)
        cipher_block = b .⊻ view(key_block, 1:length(b))
        counter += 1
        append!(ciphertext, cipher_block)
    end

    ciphertext
end
