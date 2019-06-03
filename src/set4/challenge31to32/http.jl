import HTTP
import Sockets

export http_serve, HttpRunner

# "Return a 500 if the MAC is invalid, and a 200 if it's OK."
# (What? You should return 401 Unauthorized!)
function verify_file(req::HTTP.Request)
    if verify(req.target)
        HTTP.Response(200, "You're authorized but I don't want to share the file")
    else
        HTTP.Response(401, "unauthorized")
    end
end

const FILE_ROUTER = HTTP.Router()
HTTP.@register(FILE_ROUTER, "GET", "/test", verify_file)

http_serve() = HTTP.serve(FILE_ROUTER, Sockets.localhost, 9000)

struct HttpRunner <: Runner end

function make_request(http_runner::HttpRunner, file::String, signature::Vector{UInt8})::HTTP.URI
    HTTP.URI(scheme="http", host="localhost", port="9000", path="/test",
        query=Dict("file" => file, "signature" => bytes2hex(signature)))
end

function verify_request(http_runner::HttpRunner, req::HTTP.URI)::Bool
    res = HTTP.request("GET", req; status_exception=false)
    res.status == 200
end
