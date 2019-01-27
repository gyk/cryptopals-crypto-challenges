using Random: seed!

export AesMode, encryption_oracle, encrypt_by_mode, ecb_cbc_detection_oracle, rand_aes_mode

# Julia's enum sucks
@enum AesMode begin
    ECB
    CBC
end

rand_aes_mode()::AesMode = rand([ECB, CBC])

"Generates 16-byte random AES-128 key or IV."
function gen_key_iv()::Vector{UInt8}
    rand(UInt8, 16)
end

"""
Preprocessor for plaintext that appends 5-10 bytes (count chosen randomly) before the plaintext and
5-10 bytes after the plaintext.
"""
function preprocess(plaintext::AbstractVector{UInt8})::Vector{UInt8}
    (prepend_len, append_len) = rand(5:10, 2)
    prepend = rand(UInt8, prepend_len)
    append = rand(UInt8, append_len)
    vcat(prepend, plaintext, append)
end

using CryptopalsCryptoChallenges.Set1: eval_aes_ecb

"Encrypts data under an unknown key."
encryption_oracle(plaintext) = encrypt_by_mode(plaintext, rand_aes_mode())

function encrypt_by_mode(plaintext::AbstractVector{UInt8},
                         mode::AesMode)::Vector{UInt8}
    key = gen_key_iv()
    new_text = preprocess(plaintext)
    _encrypt_impl(new_text, key, Val(mode))
end

function _encrypt_impl(text::AbstractVector{UInt8},
                       key::Vector{UInt8},
                       ::Val{ECB::AesMode})::Vector{UInt8}
    text_aligned = collect(text)
    pkcs7_padding!(text_aligned, 16)
    aes_128_ecb_encode(text_aligned, key)
end

function _encrypt_impl(text::AbstractVector{UInt8},
                       key::Vector{UInt8},
                       ::Val{CBC::AesMode})::Vector{UInt8}
    iv = gen_key_iv()
    aes_128_cbc_encode(text, key, iv)
end

"""
An ECB/CBC detection oracle that tells whether the given encryption oracle uses AES-128 ECB or CBC
mode.
"""
function ecb_cbc_detection_oracle(enc_oracle::Function)::AesMode
    block = repeat([0x1B, 0xAD, 0xC0, 0xDE], 4)
    plaintext = repeat(block, 4)  # 4 seems enough
    ciphertext = enc_oracle(plaintext)
    @assert length(ciphertext) % 16 == 0

    score = eval_aes_ecb(ciphertext)
    if score < 0.05
        CBC::AesMode
    else
        ECB::AesMode
    end
end
