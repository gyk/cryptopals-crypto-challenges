export pkcs7_remove!, InvalidPKCSPaddingException

struct InvalidPKCSPaddingException <: Exception end

function pkcs7_remove!(data::Vector{UInt8})
    pad_len = data[end]
    if pad_len <= length(data) && all((@view data[end - pad_len + 1 : end]) .== pad_len)
        resize!(data, length(data) - pad_len)
    else
        throw(InvalidPKCSPaddingException())
    end
end
