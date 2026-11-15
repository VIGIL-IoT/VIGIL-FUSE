# ESP-IDF configuration applicability review packet

Status: not started. All review fields are blank. No human decisions, adjudication, or accuracy estimates are present.

This is a post-scan supplement because the earlier ESP-IoT-Solution scan already emitted FUSE006 and FUSE007 candidates. It is not a blind holdout. The sample includes all six emitted configuration files and hash-selected controls from unsuffixed and target-specific `sdkconfig.defaults` strata. See [the frozen protocol](protocol.md), [selection manifest](selection.json), and [case links and hashes](cases.json).

Reviewers A and B must work independently and must not inspect each other's forms or machine findings. Review the pinned repository context for each linked file. Review both FUSE006 and FUSE007 in every case, including controls. Record whether the specific setting is present separately from whether the file is effective for a built or deployed product. A default file alone supports at most `candidate` applicability. Use `unknown` when build evidence is absent.

Submit the completed [reviewer A form](reviewer-a.csv) and [reviewer B form](reviewer-b.csv) separately. Complete [adjudication](adjudication.csv) only after both forms are locked. Do not treat this enriched post-scan sample as field precision or recall evidence.
