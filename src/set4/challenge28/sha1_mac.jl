using SHA: sha1

export sha1_mac

function sha1_mac(message::AbstractVector{UInt8}, key::Vector{UInt8})::Vector{UInt8}
    sha1([key; message])
end
