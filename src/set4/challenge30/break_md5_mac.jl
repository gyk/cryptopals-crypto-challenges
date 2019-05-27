# I can't find an implementation of MD4 in pure Julia, so solve it on MD5 instead.
#
#
# The code in almost the same as Challenge 29. The only differences are:
#
# 1. MD5 padding is in little endian.
# 2. MD5 digest is 128-bits in length, compared with SHA1's 160-bits.

include("MD5/MD5.jl")

using ..Set4.MD5: md5, MD5_CTX, update!, digest!

export md5_mac, forge_md5

const MESSAGE = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
const FORGE = ";admin=true"
const FORGED_MESSAGE = MESSAGE * FORGE

function md5_mac(message::AbstractVector{UInt8}, key::Vector{UInt8})::Vector{UInt8}
    md5([key; message])
end

# The message length is always a multiple of 8 bits, so this function works at byte level.
# The length after padding should be congruent to -8 (56) bytes (mod 64 B).
function compute_md5_padding_len(len::Int)
    # +1 for the bit '1' (0x80)
    padding_len_minus_1 = mod(56 - (len + 1), 64)
    # +8 for message length
    padding_len_minus_1 + 1 + 8
end

function compute_md5_padding(len::Int)
    padding_len = compute_md5_padding_len(len)
    padding = zeros(UInt8, padding_len)

    padding[1] = UInt8(0x80)
    len_bits = len * 8
    padding[end - (8 - 1) : end] .= reinterpret(UInt8, [htol(len_bits)])

    padding
end

function dump_md5_state(md5::Vector{UInt8})::Vector{UInt32}
    state = reinterpret(UInt32, md5)
end

# Returns forged message and its corresponding MD5 digest, represented as a pair.
function forge_md5(md5_mac_oracle::Function)::Union{Nothing, Tuple{Vector{UInt8}, Vector{UInt8}}}
    message = Vector{UInt8}(MESSAGE)
    forge = Vector{UInt8}(FORGE)

    msg_len = length(message)
    ori_md5 = md5_mac_oracle(message)
    ori_state = dump_md5_state(ori_md5)

    # guesses the key length
    for key_len in 1:60
        ori_md5_padding = compute_md5_padding(msg_len + key_len)
        forged_message_no_key = [message; ori_md5_padding; forge]

        expected_forged_md5 = md5_mac_oracle(forged_message_no_key)

        @assert compute_md5_padding_len(msg_len + key_len + length(ori_md5_padding)) == 64

        forged_md5_ctx = MD5_CTX()
        forged_md5_ctx.state = copy(ori_state)
        forged_md5_ctx.bytecount = msg_len + key_len + length(ori_md5_padding)

        update!(forged_md5_ctx, forge)
        forged_md5 = digest!(forged_md5_ctx)

        if forged_md5 == expected_forged_md5
            return (forged_message_no_key, forged_md5)
        end
    end

    nothing
end
