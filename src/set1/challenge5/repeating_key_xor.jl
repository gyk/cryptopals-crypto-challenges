export repeating_key_xor, repeating_key_xor!

function repeating_key_xor(text::AbstractVector{UInt8},
                           key::AbstractVector{UInt8},
                           )::Vector{UInt8}
    map(xor, text, Iterators.cycle(key))
end

"An in-place version of `repeating_key_xor`."
function repeating_key_xor!(text::AbstractVector{UInt8},
                            key::AbstractVector{UInt8})
    map(((i, j),) -> text[i] ⊻= key[j],
        zip(1:length(text), Iterators.cycle(1:length(key))))
end
