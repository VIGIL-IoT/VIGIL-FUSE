# Firmware analysis boundaries

FUSE has two separate firmware paths. They must not be interpreted as equivalent.

## Directory candidate inventory

Repository scans recognize common firmware-like file extensions across the project and selected build-output directories. The candidate inventory records path, extension, size, and bounded counts. It does not open, hash, identify, extract, emulate, or validate those candidate bytes.

## Explicit image analysis

When a user selects one firmware image and enables `--firmware`, FUSE records a digest and can invoke the optional Binwalk executable for signature identification. The image size is checked against the configured firmware limit before hashing or analyzer execution. Binwalk runs without extraction. A signature match is not a complete filesystem inventory or proof that a particular device runs the image.

An optional in-toto/SLSA statement can be compared with the selected image digest using `--provenance`. A subject digest match means only that the statement names that digest. FUSE does not authenticate an envelope, verify a trusted builder, or evaluate a build policy.

## Safety boundary

FUSE never executes firmware and currently has no built-in extraction feature. Do not treat the optional Binwalk process as an OS sandbox. For hostile firmware, use a current trusted Binwalk installation in a disposable, unprivileged environment with its own resource limits.

Any future extraction feature needs a separate design and tests for path traversal, symbolic links, recursive archives, output byte and file-count caps, time limits, and cleanup. It must not execute extracted content.
