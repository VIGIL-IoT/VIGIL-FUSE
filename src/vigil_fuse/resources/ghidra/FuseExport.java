// Copyright (c) VIGIL-IoT contributors.
// This FUSE-owned script uses documented Ghidra APIs and is not copied from Ghidra.

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public class FuseExport extends HeadlessScript {
    private static final int MAX_FUNCTIONS = 2048;
    private static final int MAX_SYMBOLS = 1024;
    private static final int MAX_IMPORTS = 1024;
    private static final int MAX_EXPORTS = 1024;
    private static final int MAX_STRINGS = 1024;
    private static final int MAX_STRING_SCAN_ITEMS = 100000;
    private static final int MAX_REFERENCES = 2048;
    private static final int MAX_API_REFERENCES = 512;
    private static final int MAX_MEMORY_BLOCKS = 256;
    private static final int MAX_NAME_CHARS = 128;
    private static final int MAX_STRING_CHARS = 256;
    private static final int MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
    private static final Pattern SECRET_ASSIGNMENT = Pattern.compile(
        "(?i)(password|passwd|api[_-]?key|access[_-]?token|secret|authorization|private[_-]?key)\\s*[:=]"
    );
    private static final Pattern JWT = Pattern.compile(
        "\\b[A-Za-z0-9_-]{15,}\\.[A-Za-z0-9_-]{15,}\\.[A-Za-z0-9_-]{10,}\\b"
    );

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length != 4) {
            throw new IllegalArgumentException("Expected output path, input digest, input format, and input size");
        }
        Path output = Path.of(args[0]);
        String digest = args[1];
        String inputFormat = args[2];
        long inputSize = Long.parseLong(args[3]);
        Program program = getCurrentProgram();
        if (program == null) {
            throw new IllegalStateException("Headless analysis did not provide an imported program");
        }

        String document = buildDocument(program, digest, inputFormat, inputSize);
        byte[] bytes = (document + "\n").getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_OUTPUT_BYTES) {
            throw new IOException("Structured Ghidra result exceeded the FUSE output byte limit");
        }
        Files.write(output, bytes);
        println("FUSE Ghidra evidence exported: " + bytes.length + " bytes");
    }

    private String buildDocument(Program program, String digest, String inputFormat, long inputSize)
        throws Exception {
        List<String> entryPoints = collectEntryPoints(program);
        BoundedRecords functions = collectFunctions(program);
        BoundedRecords symbols = collectSymbols(program);
        BoundedRecords imports = collectExternalSymbols(program, true);
        BoundedRecords exports = collectExternalSymbols(program, false);
        StringCollection strings = collectStrings(program);
        BoundedRecords references = collectStringReferences(program, strings.addresses);
        BoundedRecords apiReferences = collectApiReferences(program);
        BoundedRecords memoryBlocks = collectMemoryBlocks(program);
        boolean timedOut = analysisTimeoutOccurred();
        boolean partial = timedOut || functions.truncated || symbols.truncated || imports.truncated
            || exports.truncated || strings.records.truncated || references.truncated
            || apiReferences.truncated || memoryBlocks.truncated;

        StringBuilder json = new StringBuilder(65536);
        json.append("{\"schema_version\":\"1.0\",");
        json.append("\"tool\":{\"name\":\"Ghidra\",\"version\":")
            .append(quote(getGhidraVersion())).append("},");
        json.append("\"input\":{\"sha256\":").append(quote(digest))
            .append(",\"format\":").append(quote(inputFormat))
            .append(",\"byte_size\":").append(inputSize).append("},");
        json.append("\"analysis\":{\"status\":").append(quote(partial ? "partial" : "completed"))
            .append(",\"timeout_occurred\":").append(timedOut)
            .append(",\"loader\":").append(quote(program.getExecutableFormat()))
            .append(",\"processor\":").append(quote(program.getLanguage().getProcessor().toString()))
            .append(",\"language_id\":").append(quote(program.getLanguageID().getIdAsString()))
            .append(",\"compiler_spec\":").append(quote(program.getCompilerSpec().getCompilerSpecID().toString()))
            .append(",\"endianness\":").append(quote(program.getLanguage().isBigEndian() ? "big" : "little"))
            .append(",\"pointer_size_bytes\":")
            .append(program.getAddressFactory().getDefaultAddressSpace().getPointerSize())
            .append(",\"image_base\":").append(quote(program.getImageBase().toString()))
            .append(",\"entry_points\":").append(stringArray(entryPoints))
            .append(",\"warnings\":").append(stringArray(timedOut
                ? List.of("Ghidra analysis reached its configured per-file timeout.")
                : List.of()))
            .append(",\"errors\":[]},");
        json.append("\"memory_blocks\":").append(memoryBlocks.toJson()).append(',');
        json.append("\"functions\":").append(functions.toJson()).append(',');
        json.append("\"symbols\":").append(symbols.toJson()).append(',');
        json.append("\"imports\":").append(imports.toJson()).append(',');
        json.append("\"exports\":").append(exports.toJson()).append(',');
        json.append("\"strings\":").append(strings.records.toJson()).append(',');
        json.append("\"cross_references\":").append(references.toJson()).append(',');
        json.append("\"api_references\":").append(apiReferences.toJson()).append(',');
        json.append("\"limits\":{\"max_functions\":").append(MAX_FUNCTIONS)
            .append(",\"max_symbols\":").append(MAX_SYMBOLS)
            .append(",\"max_imports\":").append(MAX_IMPORTS)
            .append(",\"max_exports\":").append(MAX_EXPORTS)
            .append(",\"max_strings\":").append(MAX_STRINGS)
            .append(",\"max_string_scan_items\":").append(MAX_STRING_SCAN_ITEMS)
            .append(",\"max_cross_references\":").append(MAX_REFERENCES)
            .append(",\"max_api_references\":").append(MAX_API_REFERENCES)
            .append(",\"max_memory_blocks\":").append(MAX_MEMORY_BLOCKS)
            .append(",\"max_name_chars\":").append(MAX_NAME_CHARS)
            .append(",\"max_string_chars\":").append(MAX_STRING_CHARS)
            .append(",\"max_output_bytes\":").append(MAX_OUTPUT_BYTES).append("},");
        json.append("\"truncation\":{\"memory_blocks\":").append(memoryBlocks.truncated)
            .append(",\"functions\":").append(functions.truncated)
            .append(",\"symbols\":").append(symbols.truncated)
            .append(",\"imports\":").append(imports.truncated)
            .append(",\"exports\":").append(exports.truncated)
            .append(",\"strings\":").append(strings.records.truncated)
            .append(",\"cross_references\":").append(references.truncated)
            .append(",\"api_references\":").append(apiReferences.truncated).append("}}");
        return json.toString();
    }

    private List<String> collectEntryPoints(Program program) {
        List<String> values = new ArrayList<>();
        AddressIterator iterator = program.getSymbolTable().getExternalEntryPointIterator();
        while (iterator.hasNext() && values.size() < MAX_EXPORTS) {
            values.add(iterator.next().toString());
        }
        return values;
    }

    private BoundedRecords collectFunctions(Program program) {
        List<String> values = new ArrayList<>();
        FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
        int observed = 0;
        while (iterator.hasNext()) {
            Function function = iterator.next();
            observed++;
            if (values.size() == MAX_FUNCTIONS) {
                break;
            }
            values.add("{\"name\":" + quote(limit(function.getName(), MAX_NAME_CHARS))
                + ",\"entry_address\":" + quote(function.getEntryPoint().toString())
                + ",\"external\":" + function.isExternal()
                + ",\"thunk\":" + function.isThunk() + "}");
        }
        return new BoundedRecords(values, observed, observed > MAX_FUNCTIONS);
    }

    private BoundedRecords collectSymbols(Program program) {
        List<String> values = new ArrayList<>();
        SymbolIterator iterator = program.getSymbolTable().getAllSymbols(true);
        int observed = 0;
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            observed++;
            if (values.size() == MAX_SYMBOLS) {
                break;
            }
            values.add(symbolJson(symbol));
        }
        return new BoundedRecords(values, observed, observed > MAX_SYMBOLS);
    }

    private BoundedRecords collectExternalSymbols(Program program, boolean imports) {
        List<String> values = new ArrayList<>();
        SymbolIterator iterator = program.getSymbolTable().getAllSymbols(true);
        Set<String> entryPoints = new HashSet<>(collectEntryPoints(program));
        int observed = 0;
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            boolean selected = imports ? symbol.isExternal()
                : entryPoints.contains(symbol.getAddress().toString());
            if (!selected) {
                continue;
            }
            observed++;
            int limit = imports ? MAX_IMPORTS : MAX_EXPORTS;
            if (values.size() == limit) {
                break;
            }
            values.add(symbolJson(symbol));
        }
        int limit = imports ? MAX_IMPORTS : MAX_EXPORTS;
        return new BoundedRecords(values, observed, observed > limit);
    }

    private String symbolJson(Symbol symbol) {
        return "{\"name\":" + quote(limit(symbol.getName(), MAX_NAME_CHARS))
            + ",\"address\":" + quote(symbol.getAddress().toString())
            + ",\"type\":" + quote(symbol.getSymbolType().toString())
            + ",\"external\":" + symbol.isExternal()
            + ",\"entry_point\":" + symbol.isExternalEntryPoint() + "}";
    }

    private StringCollection collectStrings(Program program) {
        List<String> values = new ArrayList<>();
        List<Address> addresses = new ArrayList<>();
        DataIterator iterator = program.getListing().getDefinedData(true);
        int observed = 0;
        int visited = 0;
        boolean truncated = false;
        while (iterator.hasNext()) {
            if (++visited > MAX_STRING_SCAN_ITEMS) {
                truncated = true;
                break;
            }
            Data data = iterator.next();
            Object value = data.getValue();
            if (!(value instanceof String)) {
                continue;
            }
            observed++;
            if (values.size() == MAX_STRINGS) {
                truncated = true;
                break;
            }
            Address dataAddress = data.getAddress();
            String address = dataAddress.toString();
            String text = limit((String) value, MAX_STRING_CHARS);
            values.add("{\"address\":" + quote(address)
                + ",\"value\":" + quote(redact(text))
                + ",\"redacted\":" + !redact(text).equals(text) + "}");
            addresses.add(dataAddress);
        }
        return new StringCollection(
            new BoundedRecords(values, observed, truncated || observed > MAX_STRINGS), addresses
        );
    }

    private BoundedRecords collectStringReferences(Program program, List<Address> stringAddresses) {
        List<String> values = new ArrayList<>();
        int observed = 0;
        for (Address address : stringAddresses) {
            String addressText = address.toString();
            ReferenceIterator iterator = program.getReferenceManager().getReferencesTo(address);
            while (iterator.hasNext()) {
                Reference reference = iterator.next();
                Function function = program.getFunctionManager()
                    .getFunctionContaining(reference.getFromAddress());
                if (function == null) {
                    continue;
                }
                observed++;
                if (values.size() == MAX_REFERENCES) {
                    return new BoundedRecords(values, observed, true);
                }
                values.add("{\"string_address\":" + quote(addressText)
                    + ",\"from_address\":" + quote(reference.getFromAddress().toString())
                    + ",\"function\":" + quote(limit(function.getName(), MAX_NAME_CHARS))
                    + ",\"function_entry_address\":" + quote(function.getEntryPoint().toString())
                    + ",\"reference_type\":" + quote(reference.getReferenceType().toString()) + "}");
            }
        }
        return new BoundedRecords(values, observed, false);
    }

    private BoundedRecords collectApiReferences(Program program) {
        List<String> values = new ArrayList<>();
        SymbolIterator iterator = program.getSymbolTable().getAllSymbols(true);
        int observed = 0;
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            if (!symbol.isExternal() || !isSelectedApi(symbol.getName())) {
                continue;
            }
            ReferenceIterator references = program.getReferenceManager()
                .getReferencesTo(symbol.getAddress());
            while (references.hasNext()) {
                Reference reference = references.next();
                Function function = program.getFunctionManager()
                    .getFunctionContaining(reference.getFromAddress());
                if (function == null) {
                    continue;
                }
                observed++;
                if (values.size() == MAX_API_REFERENCES) {
                    return new BoundedRecords(values, observed, true);
                }
                values.add("{\"symbol\":" + quote(limit(symbol.getName(), MAX_NAME_CHARS))
                    + ",\"address\":" + quote(symbol.getAddress().toString())
                    + ",\"function\":" + quote(limit(function.getName(), MAX_NAME_CHARS))
                    + ",\"function_entry_address\":" + quote(function.getEntryPoint().toString()) + "}");
            }
        }
        return new BoundedRecords(values, observed, false);
    }

    private boolean isSelectedApi(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        return lower.contains("http") || lower.contains("mqtt") || lower.contains("ssl")
            || lower.contains("tls") || lower.contains("socket") || lower.contains("connect")
            || lower.contains("send") || lower.contains("recv") || lower.contains("uart")
            || lower.contains("jtag") || lower.contains("debug") || lower.contains("ota")
            || lower.equals("system") || lower.contains("exec") || lower.contains("strcpy")
            || lower.contains("sprintf");
    }

    private BoundedRecords collectMemoryBlocks(Program program) {
        List<String> values = new ArrayList<>();
        MemoryBlock[] blocks = program.getMemory().getBlocks();
        int observed = 0;
        for (MemoryBlock block : blocks) {
            observed++;
            if (values.size() == MAX_MEMORY_BLOCKS) {
                break;
            }
            values.add("{\"name\":" + quote(limit(block.getName(), MAX_NAME_CHARS))
                + ",\"start\":" + quote(block.getStart().toString())
                + ",\"end\":" + quote(block.getEnd().toString())
                + ",\"byte_size\":" + block.getSize()
                + ",\"initialized\":" + block.isInitialized()
                + ",\"read\":" + block.isRead()
                + ",\"write\":" + block.isWrite()
                + ",\"execute\":" + block.isExecute() + "}");
        }
        return new BoundedRecords(values, observed, observed > MAX_MEMORY_BLOCKS);
    }

    private String redact(String value) {
        String normalized = value.replace('\u0000', ' ').replace('\r', ' ').replace('\n', ' ');
        if (normalized.contains("-----BEGIN ") || JWT.matcher(normalized).find()
            || SECRET_ASSIGNMENT.matcher(normalized).find()) {
            return "[redacted]";
        }
        return normalized;
    }

    private String limit(String value, int maxChars) {
        if (value == null) {
            return "";
        }
        return value.length() <= maxChars ? value : value.substring(0, maxChars);
    }

    private String stringArray(List<String> strings) {
        StringBuilder value = new StringBuilder("[");
        for (int index = 0; index < strings.size(); index++) {
            if (index > 0) {
                value.append(',');
            }
            value.append(quote(strings.get(index)));
        }
        return value.append(']').toString();
    }

    private String quote(String value) {
        StringBuilder quoted = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"': quoted.append("\\\""); break;
                case '\\': quoted.append("\\\\"); break;
                case '\b': quoted.append("\\b"); break;
                case '\f': quoted.append("\\f"); break;
                case '\n': quoted.append("\\n"); break;
                case '\r': quoted.append("\\r"); break;
                case '\t': quoted.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        quoted.append(String.format("\\u%04x", (int) character));
                    }
                    else {
                        quoted.append(character);
                    }
            }
        }
        return quoted.append('"').toString();
    }

    private static final class BoundedRecords {
        private final List<String> records;
        private final int observed;
        private final boolean truncated;

        private BoundedRecords(List<String> records, int observed, boolean truncated) {
            this.records = records;
            this.observed = observed;
            this.truncated = truncated;
        }

        private String toJson() {
            return "{\"records\":[" + String.join(",", records) + "],\"observed\":" + observed
                + ",\"reported\":" + records.size() + ",\"truncated\":" + truncated
                + ",\"observed_is_lower_bound\":" + truncated + "}";
        }
    }

    private static final class StringCollection {
        private final BoundedRecords records;
        private final List<Address> addresses;

        private StringCollection(BoundedRecords records, List<Address> addresses) {
            this.records = records;
            this.addresses = addresses;
        }
    }
}
