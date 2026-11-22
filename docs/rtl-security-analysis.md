# RTL security analysis

FUSE accepts Verilog and SystemVerilog files as analysis inputs. RTL describes hardware logic; Python FUSE interprets its security meaning and creates normal FUSE findings. The scan is static and bounded.

## Backend choice

The preferred optional parser is [Verible](https://github.com/chipsalliance/verible), using its `verible-verilog-syntax` JSON token output. FUSE consumes token locations and text, then extracts its own normalized structures. It does not depend on Verible's concrete-syntax-tree node layout, which Verible documents as subject to change. When Verible is missing, times out, exceeds the output limit, or cannot return usable tokens, FUSE falls back to its built-in bounded structural tokenizer. This fallback has no external dependency and is not a complete language implementation. `fuse doctor` reports the analyzer state, selected backend, version, and Verible availability.

Yosys is not used to parse or execute a project. FUSE reads only literal paths from `read_verilog` and explicit `hierarchy -top` values in `.ys` scripts to record build metadata. It never runs a user script. Yosys documents broad Verilog-2005 support and a smaller SystemVerilog subset, so it is not the general SystemVerilog front end. [Surelog](https://github.com/chipsalliance/Surelog) provides a broader SystemVerilog preprocessor, parser, elaborator, and UHDM flow, but its integration would add substantially more build and runtime surface than this bounded evidence extractor needs. The selected adapter therefore has no mandatory RTL tool dependency.

References: [Verible syntax tool](https://github.com/chipsalliance/verible/tree/master/verible/verilog/tools/syntax), [Yosys `read_verilog`](https://yosyshq.readthedocs.io/projects/yosys/en/0.47/cmd/read_verilog.html), and [Surelog](https://github.com/chipsalliance/Surelog).

## Inputs and inventory

The generic profile recognizes `.v`, `.vh`, `.sv`, `.svh`, and `.ys`. The `rtl` profile also selects common project metadata and constraint formats: `.xdc`, `.sdc`, `.qsf`, `.qpf`, `.pcf`, `.lpf`, and `.xpr`.

The inventory records Verilog/SystemVerilog source files, packages, testbench candidates, include directives, conditional macro names, constraint and project files, module declarations, inferred top-module candidates, and literal Yosys-declared tops. A top-module candidate is inferred from module instantiation within the analyzed source set. It may be an unused library module, and it does not establish the project's selected top.

Each RTL file is marked `PRESENT`. A file receives `BUILD_INCLUDED` only when its literal relative path appears in a selected `.ys` file's `read_verilog` command. FUSE does not infer exclusion from the absence of that metadata. Includes are inventoried but not expanded; scripts, macros, generated sources, and project-specific build systems are not elaborated.

## Extracted evidence

The normalized `hardware_inventory.rtl_analysis` report data is capped by file count, source bytes, token count, module-unit count, and evidence count. It includes:

- module, interface, program, and package names; ports; parameters; and instance connections
- `always` process kind, line, sensitivity, clock and reset candidates
- assignments and literal-vs-expression classification
- debug, JTAG, test, scan, bypass, unlock, and maintenance signals
- security-context literals or comparisons, with values redacted
- reset polarity and reset-assigned security state candidates
- simple `case (state_name)` state-machine candidates

State-machine and top-module labels are syntactic candidates. FUSE does not prove reachability, state coverage, or security properties.

## Security findings

The initial rules create candidates for contextual fixed security material (`FUSE-RTL-001`), an external debug-named input controlling a debug-named signal (`FUSE-RTL-002`), a permissive constant assigned to a security/debug control (`FUSE-RTL-003`), and a permissive value assigned to a security-related state in a detected reset branch (`FUSE-RTL-004`). Literal values are redacted from evidence and reports.

Signal names alone produce inventory evidence, not vulnerability findings. Conditional macro branches are observation-only. Findings have conservative static confidence and unknown applicability; Python owns their severity, confidence, applicability, and remediation. Review the selected build and surrounding logic before treating a candidate as a defect.

## Limits

This feature performs no formal verification, gate-level proof, timing analysis, physical FPGA proof, or runtime validation. It does not establish that source was synthesized, programmed, reachable at runtime, or physically exposed. It does not fully parse or elaborate all language constructs, expand includes/macros, resolve generated files, or interpret arbitrary build scripts. Tool unavailability leaves ordinary Python scans functional through the built-in parser.
