# Policy as code with OPA/Rego

FUSE can optionally evaluate an explicit organizational policy against a bounded, versioned view of scan evidence. The Python scanner remains responsible for collecting security evidence and producing FUSE findings. Rego decides whether that evidence meets a declared policy.

```text
FUSE evidence -> Python normalization -> OPA/Rego -> policy decisions -> Python reporting
```

Use the bundled reference policy or provide a `.rego` module or a directory containing `.rego` modules:

```sh
vigil-fuse scan path/to/project --policy reference:production-iot
vigil-fuse scan path/to/project --policy path/to/policy.rego --output-dir .fuse-results
vigil-fuse scan path/to/project --policy path/to/policies
```

The output is `policy-results.json` in the report directory. With `--output report.json`, it is written beside the selected report as `report.policy-results.json`. Policy evaluation is not available in `--plan` mode.

## Four different concepts

- **Finding:** a FUSE security observation tied to a rule and evidence. Its severity is assigned by FUSE or an advisory source and is not changed by Rego.
- **Applicability:** whether the finding is known to apply to the selected product or remains a candidate or unknown. Static evidence alone may not establish deployment or reachability.
- **Policy violation:** a decision that declared organizational policy was not met based on the supplied evidence. A violation is separate from a FUSE finding and has no vulnerability severity assigned by OPA.
- **Compliance mapping:** a user-supplied link from evidence or a policy rule to a named requirement. A mapping records that the policy was evaluated against that reference. It does not establish formal compliance or certification.

Reports use `policy evaluated`, `mapped`, and `evidence-supported` language. They do not claim that a product is certified, compliant, or approved.

## Evidence and unknown states

The input contract is [policy-input-1.0.schema.json](../src/vigil_fuse/schemas/policy-input-1.0.schema.json). It contains only normalized target kind/profile, component metadata, finding references and classification, selected coverage facts, firmware signature state, hardware debug-net candidate state, and a small supply-chain summary. It does not expose source text, raw finding evidence, arbitrary Python objects, or local target paths.

The result contract is [policy-result-1.0.schema.json](../src/vigil_fuse/schemas/policy-result-1.0.schema.json). Each policy returns a stable `policy_id`, `status` (`pass`, `fail`, or `unknown`), violations, unknown checks, and optional requirement mappings. FUSE validates and normalizes every OPA result before writing it.

Missing or incomplete evidence is `unknown`, never an automatic pass. For example, FUSE can report a plaintext `mqtt://` URI and a TLS verification bypass, but the absence of a bypass does not prove TLS verification is enabled. A debug net connected to a connector is only a file-based candidate, not proof of physical or runtime exposure. The current provenance intake compares firmware digests but does not determine whether firmware is signed or unsigned, so that policy check is unknown in current scans. The current debug inventory also does not determine external exposure. Contradictory applicability and VEX evidence for a high finding also remains unknown. A policy with known violations is `fail`; a policy with no violations but any unknown checks is `unknown`.

The bundled `production-iot` reference policy covers:

- plaintext MQTT observed in scanned evidence;
- TLS peer verification bypasses, with no-bypass evidence left unknown;
- unsigned firmware only when that state is explicitly represented;
- externally exposed debug interfaces only when exposure is explicitly represented;
- private-key PEM markers in scanned evidence;
- applicable, unresolved high or critical FUSE findings.

The last two exposure checks remain unknown when FUSE only has incomplete or indirect evidence. The policy evaluates supplied evidence, not the complete state of a deployed device.

## Custom policies

Each `.rego` file is evaluated as one independent policy module in package `fuse.policy`. It must expose `data.fuse.policy.result` with exactly these fields:

```rego
package fuse.policy

import rego.v1

result := {
    "policy_id": "org.example.device-policy",
    "status": "pass",
    "violations": [],
    "unknowns": [],
    "mappings": [],
}
```

Use `status: "fail"` with one or more violation objects shaped as `{"rule": "rule_id", "evidence_refs": ["<finding-ref>"], "message": "..."}`. Use `status: "unknown"` with an `unknowns` entry when evidence is missing or incomplete. The policy status must agree with the returned arrays. Evidence references must identify a reference in the normalized FUSE input. Mappings have `requirement`, `status` (`mapped` or `unknown`), and `evidence_refs` fields.

For a directory, each `.rego` file must be a self-contained module with a unique policy ID. Auxiliary modules and files outside the selected policy path are not loaded. Duplicate policy IDs, malformed modules, malformed or oversized output, and timed-out evaluation are rejected or reported as `unknown`.

FUSE invokes the local `opa eval` executable with an argument array. It does not run policy-provided shell commands and does not install OPA. Policy modules are limited to 256 KiB each, 1 MiB total, and 16 files; directory discovery is capped at 256 directories and 4096 entries. Normalized input is limited to 2 MiB. OPA output is limited to 256 KiB per policy and evaluation has an internal and process timeout. Capabilities exclude network, host-runtime, output-printing, and nondeterministic built-ins. These controls bound the interface but are not an operating-system memory sandbox; only run custom policies you trust.

Check the optional engine with `vigil-fuse doctor`. Without OPA, ordinary scans work normally. A scan that explicitly requests a policy writes an `unknown` evaluation and returns status 2 if OPA is missing or the decision is indeterminate. A policy `fail` returns status 1.

## External requirement references

An organization may put references such as OWASP IoT, ETSI EN 303 645, NIST guidance, IEC 62443, SPARTA, or its own control identifiers in `mappings`. Keep the citation, edition, interpretation, and evidence criteria under the policy owner's control. FUSE records those references as mappings only; it does not determine certification or formal compliance.
