module FuseResearch
using JSON3, Random, CSV
export load_input, graph, rank_actions, simulate, compare_planners, write_result
const NODE_TYPES = Set(["source", "build-config", "binary", "firmware", "hardware-component", "peripheral", "network-endpoint", "finding", "evidence", "device-tree-resource", "physical-interface"])
const EDGE_TYPES = Set(["contains", "builds-into", "references", "connects-to", "maps-to", "supports", "contradicts", "depends-on", "physically-reaches"])
const LIMITATIONS = ["Research recommendations are not security verdicts and require Python policy validation.", "Scores use supplied estimates, not measured information gain.", "Edges and simulations are simplified and do not establish causality."]
value(x, key, default) = get(x, key, default)
function bounded(x, name; low=0.0, high=1.0)
    x isa Real && isfinite(x) && low <= x <= high || throw(ArgumentError("$name must be finite and in [$low, $high]"))
    Float64(x)
end
function load_input(path)
    endswith(lowercase(path), ".json") || throw(ArgumentError("input must be JSON; CSV actions can be supplied via candidate_actions_csv"))
    data = JSON3.read(read(path, String), Dict{String,Any})
    if haskey(data, "candidate_actions_csv")
        haskey(data, "candidate_actions") && throw(ArgumentError("provide candidate_actions or candidate_actions_csv, not both"))
        csvpath = joinpath(dirname(abspath(path)), data["candidate_actions_csv"])
        data["candidate_actions"] = [Dict(string(k)=>v for (k,v) in pairs(row) if !ismissing(v)) for row in CSV.File(csvpath)]
    end
    data
end
include("../evidence_graph/graph.jl")
function rank_actions(data; strategy="voi", seed=0)
    strategy in ("random", "uncertainty", "centrality", "criticality", "voi") || throw(ArgumentError("unknown strategy"))
    g = graph(data); actions = value(data, "candidate_actions", [])
    length(actions) <= 10000 || throw(ArgumentError("too many actions"))
    nodes = Dict(string(n["id"])=>n for n in g.nodes)
    ids = Set{String}(); rng = MersenneTwister(seed); rows = []
    for a in actions
        id = string(a["id"]); isempty(id) && throw(ArgumentError("empty action id"))
        id in ids && throw(ArgumentError("duplicate action id")); push!(ids, id)
        target = string(a["target"]); haskey(nodes, target) || throw(ArgumentError("unknown action target"))
        n = nodes[target]
        cost = bounded(a["cost"], "cost"; low=nextfloat(0.0), high=1.0e12)
        gain = bounded(a["expected_information_gain"], "expected_information_gain")
        u = bounded(value(n, "uncertainty", 1.0), "uncertainty")
        c = bounded(value(n, "criticality", 0.5), "criticality")
        evidence = bounded(value(a, "available_evidence", 0.0), "available_evidence")
        deps = value(a, "dependencies", [])
        deps isa AbstractVector || throw(ArgumentError("dependencies must be an array"))
        all(x->x isa AbstractString, deps) || throw(ArgumentError("dependencies must be strings"))
        ready = all(x->x in value(data, "completed_actions", []), deps)
        utility = gain * u * c / cost
        isfinite(utility) || throw(ArgumentError("utility overflow"))
        factors = Dict("cost"=>cost, "expected_information_gain"=>gain, "uncertainty"=>u, "criticality"=>c, "available_evidence"=>evidence, "weighted_degree"=>g.degree[target], "dependencies_met"=>ready)
        score = strategy == "random" ? rand(rng) : strategy == "uncertainty" ? u : strategy == "centrality" ? g.degree[target] : strategy == "criticality" ? c : utility
        push!(rows, Dict("id"=>id, "target"=>target, "score"=>score, "expected_utility"=>utility, "factors"=>factors, "eligible"=>ready))
    end
    sort!(rows; by=r->(!r["eligible"], -r["score"], r["id"]))
    Dict("recommended_actions"=>rows, "scores"=>Dict(r["id"]=>r["score"] for r in rows), "strategy"=>strategy, "seed"=>seed, "assumptions"=>["Missing uncertainty defaults to 1, criticality to 0.5, edge confidence and available evidence to 0.", "VoI utility is expected gain times uncertainty times criticality divided by cost.", "Evidence availability is reported as context, not treated as calibrated gain."], "limitations"=>LIMITATIONS)
end
function simulate(; seed=0, trials=1000, fault_probability=0.01, detection_probability=0.8, prior=0.5, evidence_reliability=0.8, seu_probability=0.001, uncertainty_low=0.0, uncertainty_high=0.1)
    1 <= trials <= 1000000 || throw(ArgumentError("trials out of bounds"))
    p = bounded(fault_probability,"fault_probability"); d = bounded(detection_probability,"detection_probability")
    prior = bounded(prior,"prior"); rel = bounded(evidence_reliability,"evidence_reliability"); seu = bounded(seu_probability,"seu_probability")
    lo = bounded(uncertainty_low,"uncertainty_low"); hi = bounded(uncertainty_high,"uncertainty_high")
    lo <= hi || throw(ArgumentError("uncertainty_low exceeds uncertainty_high"))
    rng = MersenneTwister(seed); faults=0; detections=0; upsets=0; posterior_sum=0.0; propagated=0
    for _ in 1:trials
        fault = rand(rng) < p; faults += fault; detections += fault && rand(rng) < d
        upsets += rand(rng) < seu
        propagated += rand(rng) < (lo + rand(rng)*(hi-lo))
        # Binary symmetric evidence model; the evidence may support or contradict the latent event.
        truth = rand(rng) < prior; positive = (rand(rng) < rel) == truth
        numerator = positive ? prior*rel : prior*(1-rel)
        denominator = numerator + (positive ? (1-prior)*(1-rel) : (1-prior)*rel)
        posterior_sum += denominator == 0 ? prior : numerator/denominator
    end
    Dict("seed"=>seed,"trials"=>trials,"faults"=>faults,"detected_faults"=>detections,"seu_events"=>upsets,"uncertain_probability_events"=>propagated,"mean_posterior"=>posterior_sum/trials,"assumptions"=>Dict("fault_probability"=>p,"detection_probability"=>d,"prior"=>prior,"evidence_reliability"=>rel,"seu_probability"=>seu,"uncertainty_low"=>lo,"uncertainty_high"=>hi),"limitations"=>LIMITATIONS)
end
function compare_planners(data; seed=0)
    [merge(Dict("strategy"=>s, "seed"=>seed), Dict("action_id"=>r["id"],"rank"=>i,"score"=>r["score"],"estimated_cost"=>r["factors"]["cost"],"estimated_information_gain"=>r["factors"]["expected_information_gain"],"eligible"=>r["eligible"])) for s in ("random","uncertainty","centrality","criticality","voi") for (i,r) in enumerate(rank_actions(data;strategy=s,seed=seed)["recommended_actions"])]
end
function write_result(path, result)
    open(path, "w") do io; JSON3.pretty(io, result); write(io, '\n'); end
end
end
