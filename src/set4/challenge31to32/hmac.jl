using SHA: sha1

export hmac_sha1

function hmac(key::Vector{UInt8},
              message::AbstractVector{UInt8},
              hash_fn::Function,
              block_size::Int,
              digest_size::Int)::Vector{UInt8}
    key_len = length(key)
    if key_len > block_size
        key = hash_fn(key)
    elseif key_len < block_size
        key = [key; zeros(UInt8, block_size - key_len)]
    end

    o_key_pad = key .⊻ 0x5c  # outer padded key
    i_key_pad = key .⊻ 0x36  # inner padded key

    hash_fn([o_key_pad; hash_fn([i_key_pad; message])])
end

function hmac_sha1(key::Vector{UInt8}, message::AbstractVector{UInt8})::Vector{UInt8}
    hmac(key, message, sha1, 64, 20)
end
