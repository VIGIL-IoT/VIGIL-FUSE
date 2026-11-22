# FUSE polyglot platform

FUSE separates the code that interprets security evidence from the specialized analysis targets and execution tools.

| Language or target | Responsibility | Current state on this branch |
| --- | --- | --- |
| Python | Security intelligence, evidence normalization, severity, confidence, applicability, findings, remediation, and reports | Implemented core. Python also normalizes RTL parser output. |
| Go | Distributed execution | Architectural responsibility. No Go implementation is present in this checkout. |
| C++ | C/C++ semantic analysis | Architectural responsibility. No C++ analyzer implementation is present in this checkout. |
| Java | Ghidra bridge | Implemented as the optional Ghidra export program. |
| Verilog/SystemVerilog | RTL/FPGA security-analysis target | RTL is analyzed as input material. It is not used to implement the FUSE core. |

The boundary is:

> RTL tools describe hardware logic. Python FUSE interprets its security meaning.

## RTL analysis path

FUSE inventories `.v`, `.vh`, `.sv`, and `.svh` files separately from FPGA project and constraint files. It extracts bounded source structure and records candidate evidence under the normal `hardware_inventory.rtl_analysis` report object. Python assigns finding severity, confidence, applicability, and remediation. A debug, test, scan, or JTAG name by itself is an inventory observation, not a vulnerability.

The optional Verible syntax tool can provide structured tokens for source extraction. If it is absent or cannot parse a file, FUSE uses its built-in structural token parser. Neither backend elaborates a complete project. Literal Yosys `read_verilog` references can mark a present file `BUILD_INCLUDED`; otherwise the file remains `PRESENT`. The latter does not mean excluded.

This path does not perform formal verification, gate-level proof, timing analysis, physical FPGA validation, or runtime validation. It does not claim that a selected source was programmed into a device, is reachable, or is physically exposed. See the [RTL analysis guide](../rtl-security-analysis.md) for evidence categories and backend limits.
