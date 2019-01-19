import Base64

export hex2base64

"Converts a byte vector of hex string to a byte vector of base64 encoded string."
function hex2base64(hex_bytes::AbstractVector{UInt8})::Vector{UInt8}
    io = IOBuffer()
    b64_encoder = Base64.Base64EncodePipe(io)
    write(b64_encoder, hex2bytes(hex_bytes))
    close(b64_encoder)
    take!(io)
end
