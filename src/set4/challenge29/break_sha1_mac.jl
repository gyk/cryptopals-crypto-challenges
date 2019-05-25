using SHA: SHA1_CTX, update!, digest!

export forge_sha1

const MESSAGE = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
const FORGE = ";admin=true"
const FORGED_MESSAGE = MESSAGE * FORGE

# The message length is always a multiple of 8 bits, so this function works at byte level.
# The length after padding should be congruent to -8 (56) bytes (mod 64 B).
function compute_sha1_padding_len(len::Int)
    # +1 for the bit '1' (0x80)
    padding_len_minus_1 = mod(56 - (len + 1), 64)
    # +8 for message length
    padding_len_minus_1 + 1 + 8
end

function compute_sha1_padding(len::Int)
    padding_len = compute_sha1_padding_len(len)
    padding = zeros(UInt8, padding_len)

    padding[1] = UInt8(0x80)
    len_bits = len * 8
    padding[end - (8 - 1) : end] .= reinterpret(UInt8, [hton(len_bits)])

    padding
end

function dump_sha1_state(sha1::Vector{UInt8})::Vector{UInt32}
    state = reinterpret(UInt32, sha1)
    map!(bswap, state, state)
end

# Returns forged message and its corresponding SHA1 digest, represented as a pair.
function forge_sha1(sha1_mac_oracle::Function)::Union{Nothing, Tuple{Vector{UInt8}, Vector{UInt8}}}
    message = Vector{UInt8}(MESSAGE)
    forge = Vector{UInt8}(FORGE)

    msg_len = length(message)
    ori_sha1 = sha1_mac_oracle(message)
    ori_state = dump_sha1_state(ori_sha1)

    # guesses the key length
    for key_len in 1:60
        ori_sha1_padding = compute_sha1_padding(msg_len + key_len)
        forged_message_no_key = [message; ori_sha1_padding; forge]

        expected_forged_sha1 = sha1_mac_oracle(forged_message_no_key)

        @assert compute_sha1_padding_len(msg_len + key_len + length(ori_sha1_padding)) == 64

        # NOTE: The `w` field of `SHA1_CTX` will be set in `transform!` so it's unnecessary to set
        # it here.
        forged_sha1_ctx = SHA1_CTX()
        forged_sha1_ctx.state = copy(ori_state)
        forged_sha1_ctx.bytecount = msg_len + key_len + length(ori_sha1_padding)

        update!(forged_sha1_ctx, forge)
        forged_sha1 = digest!(forged_sha1_ctx)

        if forged_sha1 == expected_forged_sha1
            return (forged_message_no_key, forged_sha1)
        end
    end

    nothing
end
