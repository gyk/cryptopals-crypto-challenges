using ..Set3.MersenneTwister

export mt19937_cipher, recover_mt19937_seed,
    generate_password_reset_token, is_valid_password_reset_token

function mt19937_cipher(data::AbstractVector{UInt8}, key::UInt16)
    mt = MtRandom(UInt32(key))
    [data[i] ⊻ (extract_number!(mt) % UInt8) for i in 1:length(data)]
end

"Recovers the key (MT19937 seed) of the cipher function."
function recover_mt19937_seed(ciphertext::AbstractVector{UInt8},
                              known_plaintext::Vector{UInt8})::Union{UInt16, Nothing}
    plain_len = length(known_plaintext)
    leading_len = length(ciphertext) - plain_len
    @assert leading_len >= 0
    key_stream = ciphertext[end - plain_len + 1 : end] .⊻ known_plaintext

    for key in typemin(UInt16):typemax(UInt16)
        mt = MtRandom(UInt32(key))
        for i in 1:leading_len
            extract_number!(mt)
        end

        for i in 1:plain_len
            if extract_number!(mt) % UInt8 != key_stream[i]
                @goto next_key
            end
        end
        return key
        @label next_key
    end
    nothing
end

################################

# Not sure whether I understand the next two tasks correctly

const PASSWORD_RESET = Vector{UInt8}("FACEBOOK_STORE_PASSWORDS_IN_PLAINTEXT")

function generate_password_reset_token()::Vector{UInt8}
    seed = floor(Int, time()) % UInt16
    mt = MtRandom(UInt32(seed))
    [PASSWORD_RESET[i] ⊻ (extract_number!(mt) % UInt8) for i in 1:length(PASSWORD_RESET)]
end

function is_valid_password_reset_token(token::Vector{UInt8})::Bool
    key_stream = token .⊻ PASSWORD_RESET
    now = floor(Int, time()) % UInt16
    key = now
    while true
        mt = MtRandom(UInt32(key))
        key -= UInt16(1)

        for i in 1:length(token)
            if extract_number!(mt) % UInt8 != key_stream[i]
                @goto next_key
            end
        end
        return true

        @label next_key
        key == now && break
    end
    false
end
