using Test, FuseResearch, JSON3
const fixture = joinpath(@__DIR__, "..", "fixtures", "synthetic.json")
@testset "research engine" begin
    data = load_input(fixture); g = graph(data)
    @test length(g.nodes) == 3 && length(g.edges) == 3
    @test g.degree["isolated"] == 0
    @test g.degree["firmware"] ≈ 1.8
    result = rank_actions(data)
    @test result["recommended_actions"][1]["id"] == "binary"
    @test result["scores"]["binary"] ≈ 0.8*0.9*0.9/2
    @test !last(result["recommended_actions"])["eligible"]
    @test rank_actions(data; strategy="random",seed=42) == rank_actions(data; strategy="random",seed=42)
    @test simulate(seed=42) == simulate(seed=42)
    @test length(compare_planners(data)) == 20
    @test JSON3.read(JSON3.write(result))["recommended_actions"][1]["id"] == "binary"
    equal = Dict("nodes"=>[Dict("id"=>"n","type"=>"source")], "candidate_actions"=>[Dict("id"=>id,"target"=>"n","cost"=>1,"expected_information_gain"=>0.5) for id in ["b","a"]])
    @test [r["id"] for r in rank_actions(equal)["recommended_actions"]] == ["a","b"]
    @test rank_actions(equal)["recommended_actions"][1]["factors"]["uncertainty"] == 1
    one = Dict("nodes"=>[Dict("id"=>"n","type"=>"source","uncertainty"=>1,"criticality"=>1)], "candidate_actions"=>[Dict("id"=>"obvious","target"=>"n","cost"=>1,"expected_information_gain"=>1), Dict("id"=>"expensive","target"=>"n","cost"=>100,"expected_information_gain"=>0.9)])
    @test rank_actions(one)["recommended_actions"][1]["id"] == "obvious"
    @test rank_actions(one)["scores"]["expensive"] ≈ 0.009
    one["candidate_actions"][2]["cost"] = 0.5
    @test rank_actions(one)["recommended_actions"][1]["id"] == "expensive"
    equal["candidate_actions"][1]["cost"] = 0
    @test_throws ArgumentError rank_actions(equal)
    @test_throws ArgumentError graph(Dict("nodes"=>[],"edges"=>[Dict("source"=>"x","target"=>"y","type"=>"supports")]))
    @test_throws ArgumentError simulate(trials=0)
    @test_throws ArgumentError simulate(uncertainty_low=0.9, uncertainty_high=0.1)
    mktempdir() do dir
        write(joinpath(dir,"actions.csv"), "id,target,cost,expected_information_gain\na,n,2,0.5\n")
        write(joinpath(dir,"input.json"), "{\"nodes\":[{\"id\":\"n\",\"type\":\"source\"}],\"candidate_actions_csv\":\"actions.csv\"}")
        @test rank_actions(load_input(joinpath(dir,"input.json")))["recommended_actions"][1]["id"] == "a"
    end
end
