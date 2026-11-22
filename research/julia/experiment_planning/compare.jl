using FuseResearch, CSV
length(ARGS) in (3,4) || error("usage: compare.jl INPUT.json OUTPUT.json OUTPUT.csv [SEED]")
length(unique(abspath.(ARGS[1:3]))) == 3 || error("input and output paths must differ")
data = load_input(ARGS[1]); seed = length(ARGS) == 4 ? parse(Int, ARGS[4]) : 0
rows = compare_planners(data; seed=seed)
write_result(ARGS[2], Dict("seed"=>seed,"rows"=>rows,"limitations"=>FuseResearch.LIMITATIONS))
isempty(rows) ? write(ARGS[3], "strategy,seed,action_id,rank,score,estimated_cost,estimated_information_gain,eligible\n") : CSV.write(ARGS[3], [(strategy=r["strategy"], seed=r["seed"], action_id=r["action_id"], rank=r["rank"], score=r["score"], estimated_cost=r["estimated_cost"], estimated_information_gain=r["estimated_information_gain"], eligible=r["eligible"]) for r in rows])
