// Bounded Ghidra evidence producer. No decompiler or target execution.
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import com.google.gson.Gson;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class FuseCallGraph extends HeadlessScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !args[1].matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("Expected output path and binary digest");
        }
        List<Map<String,Object>> functions = new ArrayList<>();
        List<Map<String,Object>> calls = new ArrayList<>();
        Map<String,Function> indexed = new LinkedHashMap<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        boolean truncated = analysisTimeoutOccurred();
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            if (indexed.size() >= 2048) { truncated = true; break; }
            Function f = iterator.next();
            indexed.put(f.getEntryPoint().toString(), f);
            String name = f.getName();
            if (!name.matches("[A-Za-z0-9_.$@?<>:~+\\-/]{1,128}")) name = "redacted-symbol";
            functions.add(Map.of("name", name, "address", f.getEntryPoint().toString()));
        }
        int visited = 0;
        outer: for (Function function : indexed.values()) {
            InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                monitor.checkCancelled();
                if (++visited > 100000) { truncated = true; break outer; }
                Instruction instruction = instructions.next();
                for (Reference reference : instruction.getReferencesFrom()) {
                    if (!reference.getReferenceType().isCall()) continue;
                    Function target = currentProgram.getFunctionManager().getFunctionAt(reference.getToAddress());
                    if (target == null || !indexed.containsKey(target.getEntryPoint().toString())) {
                        truncated = true; continue;
                    }
                    if (calls.size() >= 8192) { truncated = true; break outer; }
                    calls.add(Map.of("caller", function.getEntryPoint().toString(), "callee", target.getEntryPoint().toString(),
                        "site", instruction.getAddress().toString(), "indirect", reference.getReferenceType().isComputed()));
                }
            }
        }
        Map<String,Object> result = Map.of("schema_version", "fuse-ghidra-calls-1.0", "producer", "Ghidra", "sha256", args[1],
            "functions", functions, "calls", calls, "truncated", truncated);
        byte[] payload = new Gson().toJson(result).getBytes(StandardCharsets.UTF_8);
        if (payload.length > 8388608) throw new IllegalStateException("Call graph byte limit");
        Files.write(Path.of(args[0]), payload);
    }
}
