# Flight software: initial cFE call extraction

The internal `extract_bus_calls` API accepts a mapping of source paths to UTF-8 C
source bytes. It records expressions using `CFE_SB_CreatePipe`,
`CFE_SB_Subscribe`, `CFE_SB_SubscribeEx`, `CFE_SB_TransmitMsg`,
`CFE_SB_TransmitBuffer` and `CFE_MSG_SetMsgId`, preserving arguments, file and line.
Comments and quoted strings are masked when finding calls. The parser never runs
target code or a preprocessor.

The limits are 512 files, 2 MiB per file, 10 MiB total, 10,000 calls, 4,096
characters per argument list and 64 nested parentheses. Exceeding a limit or
encountering malformed input is disclosed. Results are always `partial`: matching
expressions can be declarations or inactive code, and preprocessing, types, data
flow and application ownership are not evaluated. A transmit message pointer is
not assumed to be a message ID. No trust level or privilege is inferred. This
building block does not establish security findings.

`build_bus_graph` consumes the call records and a caller-supplied mapping from file
paths to application names. It exports deterministic JSON with application, pipe,
symbolic message-expression and transmitted message-object nodes. Create-pipe,
subscribe and transmit relationships retain source file, line and API. It preserves
duplicate observations. File ownership is not inferred; calls without assignments
are omitted. Graphs are capped at 30,000 nodes and 20,000 edges and remain partial.
The same message expression in two files is only a symbolic match and does not
establish an identical runtime ID. Transmit object expressions are not linked to
message IDs by data-flow analysis. Supported `CFE_MSG_SetMsgId` expressions add a
symbolic object-to-message edge, and an identical object expression may also appear
in a transmit edge. This is a syntactic association only: execution order, aliases,
and runtime IDs are not established. Unhandled expressions and calls are disclosed
in limitations.
The graph also contains a low-confidence, unvalidated review observation when the
same pipe has multiple syntactically identical subscription calls for a symbolic
message. It reports the count and up to ten locations. Conditional or inactive
code may make these observations false positives; they do not prove a bus fault,
attack path or privilege escalation, and their severity is `unknown`.

Run `vigil-fuse flight-bus ./project --source PAYLOAD=src/payload.c`; repeat
`--source APP=PATH` to assign additional files. Paths must be inside the target.
JSON is written to standard output. Exit code `1` means partial analysis; `2`
means invalid input. The command does not build or execute source code.

An optional `--policy flight.toml` supplies component metadata and symbolic
subscription boundaries. Example:

```toml
[flight_software.components.PAYLOAD]
criticality = "medium"
trust = "low"

[flight_software.components.ADCS]
criticality = "critical"

[flight_software.messages.ADCS_CMD_MID]
allowed_subscribers = ["ADCS"]
allowed_publishers = ["ADCS"]
```

Only explicitly listed message expressions are checked, using exact symbolic
matching. An application absent from that message's configured allowlist produces
a low-confidence, unvalidated review candidate with unknown severity. This does
not establish a runtime subscription, privilege or exploitability. Criticality
and trust remain supplied metadata and do not change severity. Policies are
bounded to 256 KiB, 2,048 component/message entries and 10,000 list members; the
graph records the policy path and SHA-256.

An optional `allowed_publishers` list uses syntactically matching message-object
expressions in `CFE_MSG_SetMsgId` and transmit calls to produce a review candidate.
It is not data-flow or control-flow analysis; aliases, conditional code, message
mutation and execution order can cause false positives and false negatives. At most
20,000 publisher relationships are checked, and truncation is reported.

Current review signals cover repeated symbolic subscriptions and explicitly
configured subscriber/publisher boundaries. They do not yet check command-length
validation, command handler validation paths, generic broad subscriptions or
low-trust to flight-critical communications without corresponding explicit policy.
No F Prime parser is included.

The call interpretation is informed by NASA's [cFE Application Developers
Guide](https://github.com/nasa/cFE/blob/dev/docs/cFE%20Application%20Developers%20Guide.md),
which describes pipes, subscriptions and message transmission.
