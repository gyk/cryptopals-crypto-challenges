using CryptopalsCryptoChallenges.Set1: single_byte_xor_decrypt

export break_fixed_nonce_ctr_stat

function byte_list_at(ciphertext_list::AbstractVector{Vector{UInt8}}, i::Int)::Vector{UInt8}
    byte_list = UInt8[]
    sizehint!(byte_list, length(ciphertext_list))
    for ciphertext in ciphertext_list
        if length(ciphertext) >= i
            push!(byte_list, ciphertext[i])
        end
    end
    byte_list
end

"Returns the key stream."
function break_fixed_nonce_ctr_stat(ciphertext_list::AbstractVector{Vector{UInt8}})::Vector{UInt8}
    lengths = length.(ciphertext_list)
    min_len = minimum(lengths)
    key_stream = Array{UInt8}(undef, min_len)
    for i in 1:min_len
        byte_list = byte_list_at(ciphertext_list, i)
        key_stream[i] = single_byte_xor_decrypt(byte_list).key
    end
    key_stream
end
