module ByteAtATimeEcbDecryptionHarder

using ..Set2

export create_enc_oracle, byte_at_a_time_ecb_decrypt_harder

#===== The encryptor side =====#

# Reuses these definitions from the "simple" challenge
using ..ByteAtATimeEcbDecryptionSimple: KEY, CHAR_SET, get_block

function create_enc_oracle(secret_string::Vector{UInt8})::Function
    random_prefix = rand(UInt8, rand([22, 32, 42]))  # the length is unknown to the cracker

    function encryption_oracle(text::AbstractVector{UInt8})
        new_text = vcat(random_prefix, text, secret_string)
        pkcs7_padding!(new_text, 16)
        aes_128_ecb_encode(new_text, KEY)
    end

    encryption_oracle
end

#===== The cracker side =====#

function detect_block_size(encryption_oracle::Function)::Int
    empty_len = length(encryption_oracle(UInt8[]))
    for l in 1:64
        probe = zeros(UInt8, l)
        probe_len = length(encryption_oracle(probe))
        if probe_len > empty_len
            block_size = probe_len - empty_len
            return block_size
        end
    end
    error("Cannot detect block size")
end

using ..ByteAtATimeEcbDecryptionSimple: crack_byte_at_a_time_ecb

function byte_at_a_time_ecb_decrypt_harder(encryption_oracle::Function)::Union{String, Nothing}
    # Detects the block size.
    block_size = detect_block_size(encryption_oracle)

    # Currently `ecb_cbc_detection_oracle` can only deal with a block size of 16.
    @assert block_size == 16 "Unsupported `block_size`"
    # Makes sure it does be encoded in ECB mode.
    if ecb_cbc_detection_oracle(encryption_oracle) != ECB::AesMode
        return nothing
    end

    e0 = encryption_oracle([UInt8(0)])
    e1 = encryption_oracle([UInt8(1)])
    i_diff = findfirst(
        identity,
        map(((a, b),) -> !all(a .== b),
            Iterators.zip(
                Iterators.partition(e0, block_size),
                Iterators.partition(e1, block_size))))

    probe_len = block_size * 2
    i_probe = i_diff + 1

    probe0 = repeat([UInt8(0)], probe_len)
    probe_cipher0 = encryption_oracle(probe0)
    block0 = get_block(probe_cipher0, block_size, i_probe)

    probe1 = repeat([UInt8(1)], probe_len)
    probe_cipher1 = encryption_oracle(probe1)
    block1 = get_block(probe_cipher1, block_size, i_probe)

    @assert get_block(probe_cipher0, block_size, i_probe) ==
        get_block(encryption_oracle(repeat([UInt8(0)], block_size * 3)), block_size, i_probe + 1)

    fill_len = nothing
    for l in (probe_len - 1):-1:1
        if get_block(encryption_oracle(repeat([UInt8(0)], l)), block_size, i_probe) != block0 ||
           get_block(encryption_oracle(repeat([UInt8(1)], l)), block_size, i_probe) != block1
            fill_len = l + 1
            break
        end
    end

    @assert !isnothing(fill_len)
    fill = zeros(UInt8, fill_len)

    prefixed_enc_oracle(x) = encryption_oracle([fill; x])[block_size * i_probe + 1 : end]
    cracked = crack_byte_at_a_time_ecb(prefixed_enc_oracle, block_size)
    String(cracked)
end

end  # module
