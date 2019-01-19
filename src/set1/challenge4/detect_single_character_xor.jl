export detect_single_byte_xor

function detect_single_byte_xor(ciphered_vector::Vector{Vector{UInt8}})::String
    candidates = [single_byte_xor_decrypt(x) for x in ciphered_vector]
    (_, min_idx) = findmin(map(result -> result.score, candidates))
    candidates[min_idx].plaintext
end
