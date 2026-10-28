# Security policy

FUSE is security analysis software and may process proprietary source, configuration, SBOM, or firmware files. Do not include live credentials or private key material in a report shared outside your team.

## Reporting a vulnerability in FUSE

Please do not publish exploit details or sensitive reproduction files in a public issue. Use [GitHub's private vulnerability reporting page](https://github.com/VIGIL-IoT/VIGIL-FUSE/security/advisories/new) when private reporting is enabled for this repository. The repository owner must enable and monitor that feature in GitHub settings. If GitHub does not offer the private report form, do not post sensitive details publicly; ask the VIGIL-IoT repository maintainers to provide a private disclosure channel.

Include the affected FUSE version or commit, the relevant command and configuration, a minimal reproduction, and the observed impact. Remove credentials, private keys, and unrelated proprietary files from the report.

## Scope

Reports about unsafe parsing, command execution, path handling, secret exposure, or other security defects in FUSE are in scope. Findings produced by FUSE against a third-party project should be reported to that project's maintainers, not as a vulnerability in FUSE.

Only the latest tagged release is considered for fixes. Development-branch behavior may change before a release. The project does not promise a response or remediation timeline.
