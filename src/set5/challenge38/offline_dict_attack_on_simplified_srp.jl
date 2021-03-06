module SRPBad

using SHA: sha256

using CryptopalsCryptoChallenges.Util: convert

export run_srp_bad, run_srp_mitm

# The simplfied SRP protocol
#
# In this protocol, the server's "B" parameter doesn't depend on the password.
#
# This challenge clears up my confusion about the necessity of applying the verifier on both sides.


const G = big(2)
const K = big(3)
const N = begin
    # NIST Prime
    N_STR = """0x
    ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
    e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
    3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
    6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
    24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
    c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
    bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
    fffffffffffff
    """
    parse(BigInt, N_STR)
end

# In the database, we have stored the `email -> (salt, verifier)` mapping.

mutable struct Server
    salt::Vector{UInt8}
    verifier::BigInt

    b::Union{Nothing, BigInt}
    B::Union{Nothing, BigInt}
    A::Union{Nothing, BigInt}

    Server(salt::Vector{UInt8}, verifier::BigInt) = new(salt, verifier, nothing, nothing)
end

mutable struct Client
    email::String
    password::String

    a::Union{Nothing, BigInt}
    A::Union{Nothing, BigInt}
    B::Union{Nothing, BigInt}

    Client(email::String, password::String) = new(email, password, nothing, nothing)
end

#===== Utilities =====#
function random_msbit1(n::BigInt)::BigInt
    lower = big(1) << (ndigits(n, base=2) - 1)
    rand(lower:(n - 1))
end

function compute_x(salt::Vector{UInt8}, password::String)::BigInt
    x_h = sha256([salt; Vector{UInt8}(password)])
    convert(BigInt, x_h)
end

# Computes the password verifier.
function compute_v(x::BigInt)::BigInt
    powermod(G, x, N)
end

# Computes the random scrambling parameter. It is effectively publicly revealed.
function compute_u(A::BigInt, B::BigInt)::BigInt
    u_h = sha256([convert(Vector{UInt8}, A); convert(Vector{UInt8}, B)])
    convert(BigInt, u_h)
end

function generate_salt()::Vector{UInt8}
    rand(UInt8, 16)
end

struct MessageClientHandshake
    I::String  # user ID
    A::BigInt
end

"Client sends user ID (email) and public ephemeral value A to Server."
function client_handshake(client::Client)::MessageClientHandshake
    a = random_msbit1(N)
    A = powermod(G, a, N)

    client.a = a
    client.A = A

    MessageClientHandshake(client.email, A)
end

struct MessageServerHandshake
    s::Vector{UInt8}  # salt
    B::BigInt
end

"Server sends user's salt and public ephemeral value B to Client."
function server_handshake(server::Server, msg::MessageClientHandshake)::MessageServerHandshake
    s = server.salt
    v = server.verifier
    b = random_msbit1(N)
    B = powermod(G, b, N)

    server.A = msg.A
    server.b = b
    server.B = B

    MessageServerHandshake(s, B)
end

"Client computes the session key"
function client_resolve_key(client::Client, msg::MessageServerHandshake)::Vector{UInt8}
    a = client.a
    A = client.A
    v = compute_v(compute_x(msg.s, client.password))
    u = compute_u(A, msg.B)
    x = compute_x(msg.s, client.password)
    client.B = msg.B
    secret = powermod(msg.B, a + u * x, N)
    sha256(convert(Vector{UInt8}, secret))
end

"Server computes the session key"
function server_resolve_key(server::Server)::Vector{UInt8}
    A = server.A
    u = compute_u(A, server.B)
    secret = powermod(A * powermod(server.verifier, u, N), server.b, N)
    sha256(convert(Vector{UInt8}, secret))
end

# Makes sure the protocol works given a valid password.
function run_srp_bad()::Bool
    email = "xitler@cpc.org.cn"
    password = raw"P1NK0C0MM1E"
    salt = generate_salt()
    verifier = compute_v(compute_x(salt, password))
    server = Server(salt, verifier)
    client = Client(email, password)
    m_c2s = client_handshake(client)
    m_s2c = server_handshake(server, m_c2s)
    key_client = client_resolve_key(client, m_s2c)
    key_server = server_resolve_key(server)
    # Client and Server verify each other using HMAC-SHA256.
    key_client == key_server
end

# Since `B` is no longer related to `v`, the MITM can generate `(b, B)` pair at his will.
function run_srp_mitm(dict::AbstractVector{String})::Bool
    # Client
    email = "minitrue@cctv.com"
    real_password = rand(dict)
    client = Client(email, real_password)
    m_c2s = client_handshake(client)

    # Server
    salt = generate_salt()
    dummy_v = big(0)
    server = Server(salt, dummy_v)
    m_s2c = server_handshake(server, m_c2s)

    real_key = client_resolve_key(client, m_s2c)

    for password in dict
        server.verifier = compute_v(compute_x(salt, password))
        key = server_resolve_key(server)
        # The HMAC-SHA256 step is skipped.
        if key == real_key
            return password == real_password
        end
    end

    false
end

end  # module
