export detect_aes_ecb

# The higher the score, the more likely the ciphertext is encrypted in ECB mode.
function eval_aes_ecb(ciphertext::AbstractVector{UInt8})::Float64
    blocks = Iterators.filter(b -> length(b) == 16, Iterators.partition(ciphertext, 16))
    n_blocks = length(ciphertext) ÷ 16
    (n_blocks - length(unique(blocks))) / n_blocks
end

function detect_aes_ecb(cipher::Vector{Vector{UInt8}})::UInt
    (_, max_idx) = findmax(eval_aes_ecb.(cipher))
    max_idx
end
