export pkcs7_padding!

# FIXME: an *even* multiple of the blocksize?
function pkcs7_padding!(text::Vector{UInt8}, block_size::Integer)
    if block_size >= typemax(UInt8)
        error("`block_size` is too large")
    end

    l = length(text)
    padding_len = block_size - l % block_size
    append!(text, repeat([padding_len], padding_len))
end
