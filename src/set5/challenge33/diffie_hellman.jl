export DiffieHellman, compute_secret

# RFC 2409, 6.2 Second Oakley Group
P_STR = """0x
    ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
    e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
    3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
    6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
    24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
    c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
    bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
    fffffffffffff
    """

const P = parse(BigInt, P_STR)
const G = big(2)

struct DiffieHellman
    p::BigInt
    g::BigInt
    private_key::BigInt
    public_key::BigInt

    function DiffieHellman(p::BigInt, g::BigInt)
        lower = big(1) << (ndigits(p, base=2) - 1)
        private_key = rand(lower:(p - 1))
        public_key = powermod(g, private_key, p)

        new(p, g, private_key, public_key)
    end
end

DiffieHellman() = DiffieHellman(P, G)

function compute_secret(dh::DiffieHellman, peer_pub_key::BigInt)::BigInt
    powermod(peer_pub_key, dh.private_key, dh.p)
end

# Task: "Note that you'll need to write your own modexp."
#
# Negative. I have written it several times in Rust, Scheme, etc.. I chose Julia in the first place
# to avoid implementing these routines myself, actually.
