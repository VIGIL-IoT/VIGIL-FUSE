# Physical reachability: device-tree parsing foundation

The experimental `vigil_fuse.device_tree.parse_device_tree` API accepts bytes from a
single UTF-8 `.dts` or `.dtsi` file. It records literal node paths, labels and raw
property values, including `compatible`, `reg`, interrupts, aliases and pinctrl
references. Inputs are limited to 2 MiB, 10,000 nodes, 50,000 statements and 128
levels. It does not run `dtc`, build tooling or target code.

The internal `find_resource_candidates` helper can compare an exact literal
`compatible` string and/or a literal `reg` address. Address matching requires
explicit parent `#address-cells` and `#size-cells` and supports one or two address
cells. It does not translate `ranges`; the address is a bus cell, not necessarily
the CPU physical address. Missing cell metadata, macros and ambiguous paths do not
produce a definitive match. A unique match remains partial.

The parser does not resolve includes, preprocessor conditions or macros, overlays,
phandles, address cells, pin encodings or board wiring. Consequently every
otherwise successful result is `partial`: a literal property may be superseded or
excluded by configuration. Malformed or over-limit input is `invalid`. Unsupported
syntax can stop extraction early and is reported as partial. Callers must not
interpret an absent node or property as proof that a device or physical path is
absent. In particular, this parser alone does not establish physical reachability,
exploitability, severity or hardware behavior.

This parser is not yet integrated into the scan stage. Use a trusted, separately
built device-tree artifact and board-specific documentation for decisions until
the later stages exist and are validated.

The internal `read_netlist_topology` API extends the existing KiCad XML reader with
net names, component references and pin numbers. It uses the same bounded XML
preflight and connector heuristics as the existing netlist analyzer. Duplicate or
missing references, unnamed or duplicate nets, and repeated pins make the result
partial. Connector classification is a candidate based on reference or component
description, not proof of an accessible connector. A netlist records design
connectivity; it does not establish PCB routing or the state of a deployed board.

`correlate_physical_evidence` accepts a finding ID, resource ID, device-tree path,
component reference, pin numbers and an explicit description of the source of that
mapping. It records candidate connector paths through the supplied topology. The
caller-provided mapping is not validated or inferred from pinctrl. Results are
`PARTIAL` when a unique node and topology are present, or `UNKNOWN` when either is
missing or ambiguous. Confidence is low; literal device status is provided only as
observed text. At most 256 pins and 10,000 connection records are processed per
binding. No finding severity, applicability or validation status is changed.

For a complete literal tree and complete netlist, a connector candidate on a mapped
pin is `PHYSICALLY_EXPOSED`; a mapped pin on a net with no connector candidate is
`PHYSICALLY_INTERNAL`; a component present with no net connection for the mapped
pins is `PHYSICALLY_UNROUTED`; and an explicitly disabled device node is
`DEVICE_DISABLED`. These are design-file statuses only. Unknown or incomplete
evidence remains `UNKNOWN` or `PARTIAL`; unrecognized XML is `UNSUPPORTED`. Even
`PHYSICALLY_EXPOSED` does not establish PCB copper routing, physical access or
exploitability.

The command requires an explicit mapping and its evidence:

```sh
vigil-fuse physical-reachability ./project --dts board.dts --netlist board.net \
  --finding FUSE-1 --resource UART2 --node /soc/serial@40004400 \
  --component U1 --pin 42 --mapping-evidence "board pin map"
```

Input files must be inside the target. JSON includes the input hashes, input
statuses and limitations. Exit code `1` means partial or unknown evidence; `2`
means invalid input. Instead of `--node`, use `--compatible vendor,uart` and/or
`--mmio 0x40004400` for exact literal candidate matching. Multiple or missing
matches return `UNKNOWN`; the address is an untranslated bus address. No automatic
finding-to-driver or pinctrl resolution occurs, and the pin map remains explicit.

`scan --plan` may report advisory command hints from bounded filename metadata.
Selected-file samples are capped at 100, so absent hints do not establish that an
input is missing. The ordinary scan does not run these commands.
