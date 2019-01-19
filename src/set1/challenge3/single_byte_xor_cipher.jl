using LinearAlgebra: norm, normalize!

export single_byte_xor_decrypt, DecryptResult

# FIXME: better handling of Etaoin shrdlu
# FIXME: immutable arrays

"""
English letter frequency (<https://en.wikipedia.org/wiki/Letter_frequency>)
"""
LETTER_FREQUENCY = normalize!([
    8.167
    1.492
    2.782
    4.253
    12.702
    2.228
    2.015
    6.094
    6.966
    0.153
    0.772
    4.025
    2.406
    6.749
    7.507
    1.929
    0.095
    5.987
    6.327
    9.056
    2.758
    0.978
    2.360
    0.150
    1.974
    0.074

    12.702  # <SPACE>, slightly more frequent than letter 'E'

    0.0  # others
], 1)

SKIP = Set(",.;:'\"!?&/\n")

CHAR_SET = UInt8.(vcat('A':'Z', 'a':'z', ' '))

CHAR_TO_IDX = Dict(Iterators.zip(CHAR_SET, vcat(1:26, 1:26, 27)))
IDX_TO_CHAR = Dict(Iterators.enumerate(CHAR_SET))

function freq_vector(s::AbstractVector{UInt8})::Vector{Float64}
    freq_vec = zeros(Float64, length(LETTER_FREQUENCY))
    freq = @view freq_vec[1:(end - 1)];
    n_invalid = 0
    for ch in s
        if ch ∈ SKIP
            continue
        end

        if haskey(CHAR_TO_IDX, ch)
            freq[CHAR_TO_IDX[ch]] += 1
        else
            n_invalid += 1
        end
    end

    freq_vec[end] = n_invalid
    normalize!(freq_vec, 1)
    freq_vec
end

struct DecryptResult
    key::UInt8
    score::Float64
    plaintext::String
end

function single_byte_xor_decrypt(ciphered::AbstractVector{UInt8})::DecryptResult
    keys = collect(UInt8(1):UInt8(255))
    distances = [
        begin
            deciphered = xor.(ciphered, ch)
            norm(freq_vector(deciphered) - LETTER_FREQUENCY)
        end
        for ch in keys
    ]

    (min_val, min_idx) = findmin(distances)
    key = keys[min_idx]
    score = min_val
    plaintext = String(xor.(ciphered, key))
    DecryptResult(key, score, plaintext)
end
