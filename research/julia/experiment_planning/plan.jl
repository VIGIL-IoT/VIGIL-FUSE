using FuseResearch
length(ARGS) in (2,3) || error("usage: plan.jl INPUT.json OUTPUT.json [SEED]")
abspath(ARGS[1]) == abspath(ARGS[2]) && error("output must differ from input")
data = load_input(ARGS[1]); seed = length(ARGS) == 3 ? parse(Int, ARGS[3]) : 0
write_result(ARGS[2], rank_actions(data; seed=seed))
