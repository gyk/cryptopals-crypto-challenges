using Test
using CryptopalsCryptoChallenges.Set7

import CryptopalsCryptoChallenges.Set7.CbcMacForgery
@testset "cbc_mac_forgery" begin
    victim_req = CbcMacForgery.make_victim_legal_request()
    forged_req = CbcMacForgery.forge_request(victim_req)
    tx = CbcMacForgery.handle_request(forged_req)
    @test !isnothing(tx) && tx[1337] == 1000_000_000
end
