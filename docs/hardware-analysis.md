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
