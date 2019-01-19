import Base64
import IterTools

export bit_hamming_distance, break_repeating_key_xor

const MIN_KEY_SIZE = 2
const MAX_KEY_SIZE = 40

function bit_hamming_distance(a::AbstractVector{UInt8}, b::AbstractVector{UInt8})::UInt
    sum(@. count_ones(xor(a, b)))
end

const N_MAX_SAMPLES = 10

# The return value is of type `Int` rather than `UInt` because of `IterTools.partition`'s definition
# (which is wrong).
function guess_key_size(ciphered::AbstractVector{UInt8})::Int
    min_d = typemax(Float64)
    guessed_key_size = Nothing

    for key_size in MIN_KEY_SIZE:MAX_KEY_SIZE
        d_list = map(
            ((a, b),) -> bit_hamming_distance(a, b),
            Iterators.take(
                IterTools.partition(
                    map(collect, IterTools.partition(ciphered, key_size)),
                    2,
                    1),
                N_MAX_SAMPLES))

        normalized_d = sum(d_list) / (length(d_list) * key_size)

        if normalized_d < min_d
            min_d = normalized_d
            guessed_key_size = key_size
        end
    end
    guessed_key_size
end

function break_repeating_key_xor(ciphered::AbstractVector{UInt8})::Vector{UInt8}
    key_size = guess_key_size(ciphered)
    blocks = hcat(map(collect, IterTools.partition(ciphered, key_size))...)
    key = mapslices(x -> single_byte_xor_decrypt(x).key, blocks; dims=[2])
    key[:]
end
