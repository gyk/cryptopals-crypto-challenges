module BreakHmacSha1Timing

include("hmac.jl")

using HttpCommon: parsequerystring
using URIParser: URI

export break_hmac_sha1, Runner, HttpRunner, MockRunner

const KEY = Vector{UInt8}("Whatever")

function verify(url::String)::Bool
    url = URI(url)

    query = parsequerystring(url.query)
    try
        file = query["file"]
        signature = query["signature"]
        insecure_compare(hmac_sha1(KEY, Vector{UInt8}(file)), hex2bytes(signature))
    catch error
        if isa(error, KeyError)
            return false
        end
    end
end

"Returns `true` if `a == b`."
function insecure_compare(a::AbstractVector{UInt8}, b::AbstractVector{UInt8})::Bool
    len = min(length(a), length(b))
    for i in 1:len
        if a[i] == b[i]
            # `sleep` is very inaccurate. See <https://github.com/JuliaLang/julia/issues/12770>.
            sleep(0.05)  # sleeps 50 ms
        else
            return false
        end
    end
    true
end

function current_time_millis()
    Int64(round(time() * 1000.0))
end

abstract type Runner end

struct MockRunner <: Runner end

using Printf: @sprintf
function make_request(mock_runner::MockRunner, file::String, signature::Vector{UInt8})::String
    @sprintf "/test?file=%s&signature=%s" file bytes2hex(signature)
end

function verify_request(mock_runner::MockRunner, req::String)::Bool
    verify(req)
end

# TODO: The delay fluctuates due to network delay, GC or whatever reasons. We need to make this
# function robust.
#
# It would be better to model the delay as Guassian distribution, and compute the Median Absolute
# Deviation to estimate SD, and then find the correct guess by detecting the outliner. And when in
# doubt, increase the trial number.

function break_hmac_sha1(runner::Runner, file::String)::Vector{UInt8}
    hmac = zeros(UInt8, 20)
    # Warns up
    for i in 1:5
        make_request(runner, "dummy", hmac)
    end
    for i in 1:20
        println("i = $i, hmac = $(bytes2hex(hmac))")

        delays = [typemax(Float64) for i in 1:256]
        for b in UInt8(0):UInt8(255)
            hmac[i] = b
            request = make_request(runner, file, hmac)

            N_TRIALS = 5
            delta_list = zeros(Float64, N_TRIALS)
            for j in 1:N_TRIALS
                t = current_time_millis()
                if verify_request(runner, request)
                    return hmac
                end
                delta_list[j] = current_time_millis() - t
            end
            delta = sum(delta_list) / N_TRIALS

            delays[if b == UInt8(0); 256 else b end] = delta
        end

        (_, max_index) = findmax(delays)
        b = max_index % 256
        hmac[i] = b
    end

    println("hmac = $(bytes2hex(hmac))")
    hmac
end

include("http.jl")

end  # module
