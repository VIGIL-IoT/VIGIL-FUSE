function graph(data)
    nodes = value(data, "nodes", [])
    edges = value(data, "edges", [])
    length(nodes) <= 10000 && length(edges) <= 50000 || throw(ArgumentError("graph exceeds research bounds"))
    ids = Set{String}()
    for n in nodes
        id = string(n["id"]); isempty(id) && throw(ArgumentError("empty node id"))
        id in ids && throw(ArgumentError("duplicate node id: $id")); push!(ids, id)
        n["type"] in NODE_TYPES || throw(ArgumentError("invalid node type"))
        bounded(value(n, "uncertainty", 1.0), "uncertainty")
        bounded(value(n, "criticality", 0.5), "criticality")
    end
    degree = Dict(id=>0.0 for id in ids)
    for e in edges
        s, t = string(e["source"]), string(e["target"])
        s in ids && t in ids || throw(ArgumentError("edge references unknown node"))
        e["type"] in EDGE_TYPES || throw(ArgumentError("invalid edge type"))
        c = bounded(value(e, "confidence", 0.0), "confidence")
        degree[s] += c; degree[t] += c
    end
    (; nodes, edges, degree)
end
