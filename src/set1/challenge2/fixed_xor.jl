import Base64

export fixed_xor

@inline function fixed_xor(
    buffer1::AbstractVector{UInt8},
    buffer2::AbstractVector{UInt8})::Vector{UInt8}
    xor.(buffer1, buffer2)
end
