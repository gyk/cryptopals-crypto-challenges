using CryptopalsCryptoChallenges.Set3: aes_128_ctr

export edit, recover_plaintext

const NONCE = Int64(0)

function edit(ciphertext::AbstractVector{UInt8},
              key::AbstractVector{UInt8},
              offset::Int,
              newtext::Vector{UInt8})::Vector{UInt8}
    lower = offset - (offset - 1) % 16
    upper = begin
        upper = offset + length(newtext)
        (upper - 1 + 15) ÷ 16 * 16
    end

    @assert (upper - lower + 1) % 16 == 0
    ciphertext_view = view(ciphertext, lower:upper)
    left_len = offset - lower
    right_len = upper - (offset + length(newtext) - 1)

    counter = UInt64(lower ÷ 16)
    plaintext = aes_128_ctr(ciphertext_view, key, NONCE, counter)
    plaintext = [plaintext[1:left_len]; newtext; plaintext[(end - right_len + 1):end]]
    @assert length(plaintext) == length(ciphertext_view)
    new_ciphertext = aes_128_ctr(plaintext, key, NONCE, counter)

    [ciphertext[1:(lower - 1)]; new_ciphertext; ciphertext[(upper + 1):end]]
end

function recover_plaintext(old_ciphertext::AbstractVector{UInt8},
                           new_ciphertext::AbstractVector{UInt8},
                           offset::Int,
                           newtext::AbstractVector{UInt8})::Vector{UInt8}
    last_pos = offset + length(newtext) - 1
    newtext .⊻ (old_ciphertext[offset:last_pos] .⊻ new_ciphertext[offset:last_pos])
end
