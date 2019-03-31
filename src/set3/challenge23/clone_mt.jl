using ..Set3.MersenneTwister: MtParam

export untemper

function untemper(y::UInt32, param::MtParam)
    y = reverse_xorshift_right(y, Int(param.l))
    y = reverse_xorshift_left(y, Int(param.t), param.c)
    y = reverse_xorshift_left(y, Int(param.s), param.b)
    y = reverse_xorshift_right(y, Int(param.u), param.d)
    y
end

function reverse_xorshift_left(value::UInt32, n_shift::Int, and_mask::UInt32)::UInt32
    if n_shift == 0
        error("`n_shift` should not be 0")
    end

    n_remains::Int = 32 - n_shift
    mask = (UInt32(1) << n_shift) - UInt32(1)
    while n_remains > 0
        value ⊻= ((value & mask) << n_shift) & and_mask
        n_remains -= n_shift
        mask <<= n_shift
    end
    value
end

function reverse_xorshift_right(value::UInt32, n_shift::Int, and_mask::UInt32)::UInt32
    if n_shift == 0
        error("`n_shift` should not be 0")
    end

    n_remains::Int = 32 - n_shift
    mask = ~((UInt32(1) << n_remains) - UInt32(1))
    while n_remains > 0
        value ⊻= ((value & mask) >> n_shift) & and_mask
        n_remains -= n_shift
        mask >>= n_shift
    end
    value
end

function reverse_xorshift_left(value::UInt32, n_shift::Int)::UInt32
    if n_shift == 0
        error("`n_shift` should not be 0")
    end

    while n_shift < 32
        value ⊻= value << n_shift
        n_shift *= 2
    end
    value
end

function reverse_xorshift_right(value::UInt32, n_shift::Int)::UInt32
    if n_shift == 0
        error("`n_shift` should not be 0")
    end

    while n_shift < 32
        value ⊻= value >> n_shift
        n_shift *= 2
    end
    value
end
