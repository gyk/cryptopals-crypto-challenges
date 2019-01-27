export create_enc_oracle, byte_at_a_time_ecb_decrypt_simple

#===== The encryptor side =====#

# A very secret key
KEY = begin
    key = UInt8[
        0xB1, 0x6B, 0x00, 0xB5,
        0xCA, 0xFE, 0xBA, 0xBE,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xFE, 0xED, 0xBA, 0xBE,
    ]
    key .⊻ reverse(key)
end

function create_enc_oracle(secret_string::Vector{UInt8})::Function

    function encryption_oracle(text::AbstractVector{UInt8})
        new_text = vcat(text, secret_string)
        pkcs7_padding!(new_text, 16)
        aes_128_ecb_encode(new_text, KEY)
    end

    encryption_oracle
end

#===== The cracker side =====#

function detect_block_size(encryption_oracle::Function)::UInt
    empty_ciphertext = encryption_oracle(UInt8[])
    for i in 1:64
        t = zeros(UInt8, i)
        ciphertext = encryption_oracle(t)
        if ciphertext[end - length(empty_ciphertext) + 1 : end] == empty_ciphertext
            return i
        end
    end
end

CHAR_SET = begin
    common = UInt8['a':'z'; 'A':'Z'; ' '; '0':'9'; Set(",.;:'\"!?&/\n")...]
    remains = setdiff(Set(typemin(UInt8):typemax(UInt8)), common)
    [common; remains...]
end

"Gets the `i`-th block of the `data`."
function get_block(data::AbstractVector{UInt8}, block_size::Integer, i::Integer)::SubArray{UInt8, 1}
    view(data, (block_size * (i - 1) + 1 : block_size * i))
end

function byte_at_a_time_ecb_decrypt_simple(encryption_oracle::Function)::Union{String, Nothing}
    # Detects the block size.
    block_size = detect_block_size(encryption_oracle)

    # Makes sure it does be encoded in ECB mode.
    if ecb_cbc_detection_oracle(encryption_oracle) != ECB::AesMode
        return Nothing
    end

    # Computes the number of blocks.
    ZERO_BLOCK = zeros(UInt8, block_size)
    n_blocks = length(encryption_oracle(UInt8[])) ÷ block_size

    # Cracks it!
    cracked = UInt8[]
    sizehint!(cracked, block_size * n_blocks)
    for i_blk = 1:n_blocks
        for i_byte = 1:block_size
            encrypted = encryption_oracle(ZERO_BLOCK[1:(block_size - i_byte)])
            ref = get_block(encrypted, block_size, i_blk)

            # prepares to crack
            probe = repeat(ZERO_BLOCK, i_blk)
            @assert length(cracked) == block_size * (i_blk - 1) + (i_byte - 1)
            probe[end - length(cracked) : end - 1] .= cracked

            # tries to crack
            succeeded = false
            for ch in CHAR_SET
                probe[end] = ch
                probe_encrypted = encryption_oracle(probe)
                if get_block(probe_encrypted, block_size, i_blk) == ref
                    push!(cracked, ch)
                    succeeded = true
                    break
                end
            end
            if !succeeded
                # The last cracked character is actually a padding (0x01). We can no longer "crack"
                # further characters because now the string ends with 0x0202.
                @assert probe[end - 1] == 0x01
                pop!(cracked)
                @goto return_label
            end
        end
    end

@label return_label
    # Have you ever seen the penguins?
    return String(cracked)
end
