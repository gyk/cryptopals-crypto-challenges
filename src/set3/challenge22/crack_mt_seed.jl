using ..Set3.MersenneTwister: MtRandom, extract_number!

export generate_mt19937_random, crack_mt19937_seed

function generate_mt19937_random(wait_sec_range::UnitRange{Int})::Tuple{UInt32, UInt32}
    random_seconds() = rand(wait_sec_range)

    wait1 = random_seconds()
    sleep(wait1)

    seed = floor(Int, time()) % UInt32
    mt = MtRandom(seed)

    wait2 = random_seconds()
    sleep(wait2)

    (seed, extract_number!(mt))
end

function crack_mt19937_seed(wait_sec_range::UnitRange{Int}, number::UInt32)::Union{UInt32, Nothing}
    now  = floor(Int, time()) % Int32
    wait_range = (wait_sec_range.start * 2):(wait_sec_range.stop * 2)
    look_ahead = 10
    for seed in (now - wait_range.stop - look_ahead):(now - wait_range.start)
        mt = MtRandom(UInt32(seed))
        if extract_number!(mt) == number
            return seed
        end
    end
    Nothing
end
