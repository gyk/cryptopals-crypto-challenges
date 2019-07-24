using Nettle: trim_padding_PKCS5
using SHA: sha1

using CryptopalsCryptoChallenges.Util: convert
using CryptopalsCryptoChallenges.Set2: aes_128_cbc_encode, aes_128_cbc_decode, pkcs7_padding!

export run_dh_normal, run_dh_mitm
export ManInTheMiddle, ManInTheMiddleGEq1, ManInTheMiddleGEqP, ManInTheMiddleGEqPMinus1

const BIDU_MSG = Vector{UInt8}("What's your problem?")

mutable struct Client
    dh::Union{DiffieHellman, Nothing}

    Client() = new(nothing)
end

mutable struct Server
    dh::Union{DiffieHellman, Nothing}

    Server() = new(nothing)
end

mutable struct ManInTheMiddle
    p::Union{BigInt, Nothing}

    ManInTheMiddle() = new(nothing)
end
struct ManInTheMiddleGEq1 end
struct ManInTheMiddleGEqP end
mutable struct ManInTheMiddleGEqPMinus1
    g::Union{BigInt, Nothing}

    ManInTheMiddleGEqPMinus1() = new(nothing)
end

struct ClientHandshake
    p::BigInt
    g::BigInt
    public_key::BigInt
end

struct ServerHandshake
    public_key::BigInt
end

struct Message
    ciphertext::Vector{UInt8}
    iv::Vector{UInt8}
end

function handshake(client::Client)::ClientHandshake
    dh = DiffieHellman()
    client.dh = dh
    ClientHandshake(dh.p, dh.g, dh.public_key)
end

function handshake(server::Server, c_handshake::ClientHandshake)::ServerHandshake
    p = c_handshake.p
    g = c_handshake.g
    dh = DiffieHellman(p, g)
    server.dh = dh
    ServerHandshake(dh.public_key)
end

function compute_symmetric_key(party, handshake)::Vector{UInt8}
    peer_pub_key = handshake.public_key
    secret = compute_secret(party.dh, peer_pub_key)
    convert(Vector{UInt8}, secret)
end

#==============================================================#

"MITM: A"
function forge_handshake(mitm::ManInTheMiddle, c_handshake::ClientHandshake)
    mitm.p = c_handshake.p
    ClientHandshake(c_handshake.p, c_handshake.g, c_handshake.p)
end

# NOTE: The rule of Challenge 35 is that you can only alter `g`, but have to leave other values
# unchanged. As a result, the client and server won't obtain the identical secret key.

"MITM: g = 1"
function forge_handshake(mitm::ManInTheMiddleGEq1, c_handshake::ClientHandshake)
    # B = (1 ^ b) % p = 1
    ClientHandshake(c_handshake.p, big(1), c_handshake.public_key)
end

"MITM: g = p"
function forge_handshake(mitm::ManInTheMiddleGEqP, c_handshake::ClientHandshake)
    # B = (p ^ a) % p = 0
    ClientHandshake(c_handshake.p, c_handshake.p, c_handshake.public_key)
end

"MITM: g = p - 1"
function forge_handshake(mitm::ManInTheMiddleGEqPMinus1, c_handshake::ClientHandshake)
    # B = ((p - 1) ^ b) % p = ±1
    mitm.g = c_handshake.p - big(1)
    ClientHandshake(c_handshake.p, mitm.g, c_handshake.public_key)
end

#--------------------------------------------------------------#

forge_handshake(mitm::ManInTheMiddle, s_handshake::ServerHandshake) = ServerHandshake(mitm.p)
forge_handshake(mitm::ManInTheMiddleGEq1, s_handshake::ServerHandshake) = s_handshake
forge_handshake(mitm::ManInTheMiddleGEqP, s_handshake::ServerHandshake) = s_handshake
forge_handshake(mitm::ManInTheMiddleGEqPMinus1, s_handshake::ServerHandshake) = s_handshake

#--------------------------------------------------------------#

"MITM: A"
function guess_secrets(mitm::ManInTheMiddle)
    [UInt8[]]
end

"MITM: g = 1"
function guess_secrets(mitm::ManInTheMiddleGEq1)
    # SA = (1 ^ a) % p = 1
    [[0x01]]
end

"MITM: g = p"
function guess_secrets(mitm::ManInTheMiddleGEqP)
    # SA = (0 ^ a) % p = 0
    [UInt8[]]
end

"MITM: g = p - 1"
function guess_secrets(mitm::ManInTheMiddleGEqPMinus1)
    # SA = ((-1) ^ (a * b)) % p = ±1
    [[0x01], convert(Vector{UInt8}, mitm.g)]
end

#--------------------------------------------------------------#

has_succeeded(mitm::ManInTheMiddle, eq_flags::BitVector) = all(eq_flags)
has_succeeded(mitm::ManInTheMiddleGEq1, eq_flags::BitVector) = eq_flags[3] || eq_flags[4]
has_succeeded(mitm::ManInTheMiddleGEqP, eq_flags::BitVector) = eq_flags[3] || eq_flags[4]
has_succeeded(mitm::ManInTheMiddleGEqPMinus1, eq_flags::BitVector) = eq_flags[3] || eq_flags[4]

#==============================================================#

function run_dh_normal()
    client = Client()
    server = Server()

    client_handshake = handshake(client)  # C -> S
    server_handshake = handshake(server, client_handshake)  # S -> C

    client_secret = sha1(compute_symmetric_key(client, server_handshake))[1:16]
    server_secret = sha1(compute_symmetric_key(server, client_handshake))[1:16]
    @assert client_secret == server_secret

    client_iv = rand(UInt8, 16)
    plaintext = pkcs7_padding!(copy(BIDU_MSG), 16)
    client_ciphertext = aes_128_cbc_encode(plaintext, client_secret, client_iv)
    client_message = Message(client_ciphertext, client_iv)  # C -> S

    server_iv = rand(UInt8, 16)
    client_plaintext = aes_128_cbc_decode(client_message.ciphertext, server_secret,
        client_message.iv)
    server_ciphertext = aes_128_cbc_encode(client_plaintext, server_secret, server_iv)
    server_message = Message(server_ciphertext, server_iv)  # S -> C

    server_plaintext = aes_128_cbc_decode(server_message.ciphertext, client_secret,
        server_message.iv)
    trim_padding_PKCS5(server_plaintext) == BIDU_MSG
end

# Normal:
#
#     A = (g ^ a) % p
#     B = (g ^ b) % p
#     SA = (B ^ a) % p
#     SB = (A ^ b) % p
#     S = (g ^ (a * b)) % p
#
# MITM (Challenge 34, other cases in Challenge 35 are similar):
#
#     A' = p
#     B' = p
#     SA = (B' ^ a) % p = 0
#     SB = (A' ^ b) % p = 0
#

function run_dh_mitm(mitm)
    client = Client()
    server = Server()

    client_handshake = handshake(client)  # C -> M
    forge_c_handshake = forge_handshake(mitm, client_handshake)  # M -> S
    server_handshake = handshake(server, forge_c_handshake)  # S -> M
    forge_s_handshake = forge_handshake(mitm, server_handshake)  # M -> C

    client_secret = sha1(compute_symmetric_key(client, forge_s_handshake))[1:16]
    server_secret = sha1(compute_symmetric_key(server, forge_c_handshake))[1:16]

    client_iv = rand(UInt8, 16)
    plaintext = pkcs7_padding!(copy(BIDU_MSG), 16)
    client_ciphertext = aes_128_cbc_encode(plaintext, client_secret, client_iv)
    client_message = Message(client_ciphertext, client_iv)  # C -> M -> S

    server_iv = rand(UInt8, 16)
    client_plaintext = aes_128_cbc_decode(client_message.ciphertext, server_secret,
        client_message.iv)
    server_ciphertext = aes_128_cbc_encode(client_plaintext, server_secret, server_iv)
    server_message = Message(server_ciphertext, server_iv)  # S -> M -> C

    server_plaintext = aes_128_cbc_decode(server_message.ciphertext, client_secret,
        server_message.iv)

    eq_flags = BitVector([
        trim_padding_PKCS5(client_plaintext) == BIDU_MSG,
        trim_padding_PKCS5(server_plaintext) == BIDU_MSG,
        false,
        false,
    ])

    mitm_secrets = map(s -> sha1(s)[1:16], guess_secrets(mitm))
    for mitm_secret in mitm_secrets
        c_mitm_plaintext = aes_128_cbc_decode(client_message.ciphertext, mitm_secret,
            client_message.iv)
        s_mitm_plaintext = aes_128_cbc_decode(server_message.ciphertext, mitm_secret,
            server_message.iv)
        eq_flags[3] |= trim_padding_PKCS5(c_mitm_plaintext) == BIDU_MSG
        eq_flags[4] |= trim_padding_PKCS5(s_mitm_plaintext) == BIDU_MSG
    end

    has_succeeded(mitm, eq_flags)
end
