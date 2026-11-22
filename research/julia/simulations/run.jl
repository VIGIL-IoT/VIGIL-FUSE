using FuseResearch
length(ARGS) in (1,2) || error("usage: run.jl OUTPUT.json [SEED]")
write_result(ARGS[1], simulate(seed=length(ARGS)==2 ? parse(Int, ARGS[2]) : 0))
