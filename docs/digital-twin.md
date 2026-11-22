# Digital twin: SVD inventory foundation

The internal `parse_svd` API accepts a single explicitly supplied UTF-8 CMSIS-SVD
document as bytes and a source label. It records the SHA-256 digest, device name
and version, peripheral base addresses, interrupts, registers, access and reset
values, fields and enumerated values. Device and peripheral defaults are applied
to literal registers. It rejects DTDs and entity declarations and never downloads
vendor descriptions or runs firmware.

Inputs are capped at 10 MiB, 100,000 XML elements, 128 levels, 2,048 peripherals,
10,000 registers, 50,000 fields and 1,024 characters per extracted text field or
source label. Malformed XML, duplicate peripheral, register
or field names, and limit violations return `invalid`. Numeric literals are limited
to decimal, hexadecimal and binary values without wildcard bits. Results are
`partial`: derived definitions, arrays and register clusters are omitted; some
field range encodings, vendor extensions and other semantics are not interpreted.
No SVD schema validation or device identity matching is performed. A reset value
does not mean every bit is defined: consult the recorded reset mask.

`synthesize_digital_twin` creates a deterministic JSON-ready description of
selected peripherals and retains SVD provenance and unknown reset values. When a
BOM is supplied, exact component-name or part-number matches to the SVD device
name are recorded as candidates, not verified identity. Output is capped at 4 MiB.
The description adds no synthetic behavior and does not run firmware.

The experimental `export_renode` API emits a Renode `.repl` string for a narrow
subset of 32-bit registers with fully known reset masks and explicit caller-supplied
region sizes. Synthetic reads return those reset values, with optional explicitly
supplied ready-bit masks applied on every read; unlisted offsets return zero and
writes are ignored. The output is **synthetic emulation behavior**, not hardware
behavior. It does not model access widths, side effects, interrupts or access
permissions. It rejects unknown reset masks, overlapping or invalid regions and
unmatched overrides; it does not embed SVD names into executable script text.
Renode has not been installed or run to validate the output. No emulator execution,
QEMU exporter or scan stage invokes these APIs yet.

The noninteractive command reads only explicitly selected local files inside the
target directory and writes the intermediate JSON to standard output:

```sh
vigil-fuse digital-twin ./project --svd board.svd --peripheral USART2 --hardware-bom bom.csv
```

It returns exit code `1` for partial output and `2` for invalid input. The command
does not execute a Renode platform. To generate a synthetic platform string instead:

```sh
vigil-fuse digital-twin ./project --svd board.svd --peripheral USART2 \
  --format renode --region USART2=0x400 --ready-bit USART2.SR=0x80
```

Supply a region size for every selected peripheral. Ready-bit masks are optional,
explicit synthetic overrides; they are not inferred from source or hardware.
Generated output contains its limitations as comments and should be reviewed before
being used by an external emulator.

See Arm's [CMSIS-SVD register specification](https://arm-software.github.io/CMSIS_5/SVD/html/elem_registers.html)
for inheritance, fields, clusters and arrays.
[Renode's Python peripheral documentation](https://renode.readthedocs.io/en/latest/basic/using-python.html)
describes the platform format used by the experimental exporter.
