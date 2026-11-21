# Hardware analysis boundaries

FUSE currently provides three distinct hardware-related stages. None is a physical security assessment.

## Filename inventory

Directory scans identify recognizable schematic, PCB, CAD, BOM, netlist, HDL, and fabrication filenames. The inventory is metadata for review. FUSE does not open those files in the default stage, parse the design, or claim a vulnerability from presence alone.

## Explicit BOM import

`--hardware-bom` accepts a selected CSV or TSV and creates a CycloneDX hardware BOM artifact. This is an inventory operation. Component identity is only as reliable as the fields supplied in the BOM. Without stable manufacturer and part-number identifiers, part-level advisory matching is not assessable. Imported values can reveal board composition, so review the output before sharing it.

## KiCad XML netlist review

`--hardware-netlist` selects a KiCad XML netlist. If a project contains one unique recognized netlist, FUSE can use it for the bounded check. The parser accepts UTF-8, rejects DTD and entity declarations, and limits input to 10 MiB, 100,000 XML elements, and 128 nesting levels. CI includes fixed adversarial cases for encoding, entity declarations, structure limits, and a seeded malformed-input loop. This is a small regression corpus, not a full fuzzing campaign.

The current check emits an informational candidate when a debug-like net name such as JTAG, SWD, or UART connects to a connector-designator or connector-like component. The evidence means only that the exported design records that connectivity.

It does not establish:

- PCB copper routing or whether the net reaches a pad
- whether the connector is populated or marked do-not-populate
- whether a test point is accessible
- whether an enclosure allows physical access
- whether the debug peripheral is enabled or locked in production

Review the schematic, PCB, production fuse configuration, and physical device before drawing an exposure conclusion. FUSE does not invoke KiCad or export a netlist automatically.

## BOM advisory and external-memory checks

When a BOM is supplied, FUSE matches normalized manufacturer and part-number aliases against the built-in catalog and preserves the optional component revision in the CycloneDX hardware BOM. The initial catalog contains one sourced Espressif AR2023-005 record for classic ESP32. A family match without revision or configuration evidence remains a candidate; it does not raise severity or prove exploitability. Catalog severity is `unknown` unless evidence supports a stronger conclusion.

The BOM also identifies likely external nonvolatile memory. With a selected or uniquely discovered KiCad XML netlist, FUSE reports candidate bus-labeled nets that connect that memory and a connector-like component. It does not infer PCB routing, physical access, readable contents, encryption state, or protection configuration.

For a matching advisory, an output directory may include `sparta-mapping.json`. This contains analyst-assessed threat-technique associations with sources and unknowns. It is not a SPARTA compliance assessment.

## cFS software-bus check

`--profile cfs` enables bounded static correlation of direct cFS message initialization, transmission, and subscription calls in C/C++ source. To classify a message path, pass `--flight-bus-policy` with a project-relative JSON file, for example:

```json
{
  "version": 1,
  "applications": {
    "payload_app": {"trust_zone": "lower_trust"},
    "adcs_app": {"trust_zone": "flight_critical"}
  },
  "command_message_ids": ["0x1802"],
  "message_origin_validation": {}
}
```

Application trust zones and origin-validation states are operator declarations. Findings remain candidates with unknown severity. The parser does not resolve wrappers, generated routing, conditional compilation, runtime configuration, or deployed message authentication; review results against the mission build and its exact cFS version.

## Current scope limits

FUSE does not yet provide a full driver-to-Device-Tree-to-pin-to-PCB reachability graph, a Device Tree pinmux correlation engine, or a space-radiation and COTS hardening evidence assessor. The existing debug-interface and memory-net findings are narrow design candidates, not substitutes for those assessments. These areas require product-specific pin maps, board revisions, radiation qualification evidence, and validated deployment configuration.
