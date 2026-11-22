# Julia research engine

The independent Julia prototype reads synthetic JSON graphs and candidate actions, optionally reading actions from CSV. It writes JSON recommendations and comparison rows as JSON and CSV for later evaluation in R. It never runs external tools. No external corpus is used. Python remains the policy authority; recommendations are research hypotheses, not security findings.

## Input

A JSON object contains `nodes`, `edges`, and `candidate_actions` arrays, as illustrated by `research/julia/fixtures/synthetic.json`. Nodes have unique `id`, a `type`, and optional `uncertainty` and `criticality` values in [0,1]. Edges have `source`, `target`, `type`, and optional confidence in [0,1]. Missing edge confidence defaults to zero, expressing no supported relationship. Conflicting, cyclic and disconnected edges are retained rather than resolved. Graphs are limited to 10,000 nodes and 50,000 edges.

Actions have unique `id`, `target` node, positive finite `cost`, and `expected_information_gain` in [0,1]. Optional `available_evidence` is a [0,1] context factor. `dependencies` is an array of action IDs; the top-level `completed_actions` array records completed dependencies. Unmet dependencies make an action ineligible and place it after eligible actions. Missing uncertainty defaults to 1, criticality to 0.5, and available evidence to 0. Costs must use consistent units within one comparison. These defaults are modeling choices, not measurements.

## Methods and output

VoI is a heuristic, `expected_information_gain * uncertainty * criticality / cost`, not an estimate learned from outcomes. Alternative rankings use seeded random scores, node uncertainty, confidence-weighted degree, or criticality. Ties use action ID. Confidence-weighted degree is a local connectivity proxy, not path analysis or a measure of security importance. Actions contain score, utility, eligibility and factors, and output includes assumptions and limitations. Evidence availability is recorded but is not independently counted in the utility: expected gain is a supplied estimate that should already account for it.

The simulation draws independent Bernoulli faults, detections conditional on fault, and SEU-style events, samples a uniformly uncertain event probability between supplied bounds, and propagates a prior through a binary symmetric evidence model using Bayes' rule. Probabilities and seed are explicit arguments of `simulate`. These examples are not calibrated radiation or device reliability models: neither COTS nor radiation-hardened parts are assumed safe or unsafe. Outputs are not physical measurements.

Comparison CSV rows record strategy, action, rank, eligibility, estimated gain and cost. They are inputs to future R evaluation, not observed information gained, elapsed time, UNKNOWN reduction or confirmation rates. Those metrics require separately measured outcomes. Deterministic seeds reproduce pseudorandom results within the pinned Julia environment; they do not validate the estimates.

See the package README for commands. Inputs and outputs may contain sensitive evidence, so choose paths and sharing practices appropriate to the data. No production integration or external validation campaign is included.
