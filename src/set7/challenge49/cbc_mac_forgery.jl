module CbcMacForgery

using CryptopalsCryptoChallenges.Set2: pkcs7_padding, aes_128_ecb_encode

export
    Request, Transaction,
    handle_request, parse_query,
    cbc_mac,
    make_victim_legal_request, forge_request

# This challenge is lame. It requires sharing a common key.
KEY = Vector{UInt8}("SharingIsBetter!")

struct Request
    message::Vector{UInt8}
    mac::Vector{UInt8}
end

struct Transaction
    from_id::Int

    "to_id -> amount (do not support fractional currency)"
    tx::Dict{Int, Int}
end

function handle_request(req::Request)::Union{Nothing, Dict{Int, Int}}
    expected_mac = req.mac
    computed_mac = cbc_mac(req.message)
    if computed_mac == expected_mac
        query = String(copy(req.message))
        maybe_tx = parse_query(query)
        if !isnothing(maybe_tx)
            return maybe_tx.tx
        end
    end
    nothing
end

function parse_query(query::String)::Union{Nothing, Transaction}
    m = match(r"from=(?<from_id>\d+)&tx_list=(?<transactions>[^$]+)", query)
    if isnothing(m)
        nothing
    else
        from_id = parse(Int, m["from_id"])
        tx = Dict{Int, Int}()
        for to_amount in split(m["transactions"], ';')
            # Format: to:amount(;to:amount)*
            (to_id, amount) = split(to_amount, ':')
            try
                tx[parse(Int, to_id)] = parse(Int, amount)
            catch
                continue  # Hacker-friendly best-effort transfer policy
            end
        end
        Transaction(from_id, tx)
    end
end

# The per-message IV case
#
# "Use this fact to generate a message transferring 1M spacebucks from a target victim's account
# into your account."
#
# This one is easy, just make
#
#     iv' = m[1] .⊻ iv .⊻ m'[1]
#     m'[2:end] = m[2:end]
#
# and the MAC will not change.

# The IV = 0 case
#
# The idea is actually similar to the above case. The attacker XORs the first block of extending
# part with the MAC of a normal message from the victim, which makes the concatenated message
# computed to the same MAC as the former without being XORed.

function cbc_mac(
    plaintext::AbstractVector{UInt8},
    key::Vector{UInt8}=KEY,
)::Vector{UInt8}
    @assert length(key) == 16
    foldl((last_block, b) -> aes_128_ecb_encode(b .⊻ last_block, key),
        Iterators.partition(pkcs7_padding(plaintext, 16), 16);
        init=zeros(UInt8, 16))
end

# A legal transaction: the victim (ID: 101) transfers 5 spacebucks to her boyfriend's account (ID:
# 102).
function make_victim_legal_request()::Request
    message = Vector{UInt8}("from=101&tx_list=102:5")
    mac = cbc_mac(message)
    Request(message, mac)
end

function forge_request(legal_req::Request)::Request
    # Without losing generality, assume the attacker's account ID is 1337.
    forged_tx = Vector{UInt8}(" " ^ 16 * ";1337:1000000000")
    forged_mac = cbc_mac(forged_tx)

    victim_msg = pkcs7_padding(legal_req.message, 16)
    victim_mac = legal_req.mac
    forged_tx[1:16] .⊻= victim_mac
    forged_msg = vcat(victim_msg, forged_tx)
    Request(forged_msg, forged_mac)
end

end  # module
