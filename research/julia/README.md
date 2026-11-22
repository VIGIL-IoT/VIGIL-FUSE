# Julia research engine

This optional package investigates experiment selection using synthetic evidence. It does not launch scanners or participate in normal FUSE scans. Python remains the policy authority. Julia explores optimization and experiment-selection strategies. It does not generate production security verdicts.

See [the research design](../../docs/research/julia-research-engine.md) for the schema, methods, assumptions and limitations. Tested with Julia 1.10.10; use a Julia 1.10 environment and instantiate the pinned manifest:

```powershell
julia --project=research/julia -e 'using Pkg; Pkg.instantiate(); Pkg.test()'
julia --project=research/julia research/julia/value_of_information/run.jl research/julia/fixtures/synthetic.json result.json 42
julia --project=research/julia research/julia/experiment_planning/plan.jl research/julia/fixtures/synthetic.json plan.json 42
julia --project=research/julia research/julia/experiment_planning/compare.jl research/julia/fixtures/synthetic.json comparison.json comparison.csv 42
julia --project=research/julia research/julia/simulations/run.jl simulation.json 42
```

Outputs are explicit paths and are overwritten if present. The JSON graph is mandatory; candidate actions may instead be supplied as a CSV named by `candidate_actions_csv`, relative to the JSON file. CSV supports scalar action fields; use JSON for dependency arrays.
