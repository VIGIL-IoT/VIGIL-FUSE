# Independent review packet

Status: not started. No human decisions, agreement or accuracy estimates exist.

Reviewers A and B must be independent people, work separately, and not inspect machine observations or each other's forms. Use cases.json for pinned source URLs and hashes. Source is linked, not copied. Review the complete file, including no-finding candidates, using the frozen rule descriptions in the repository's docs/rules.md at the recorded FUSE revision.

For each case/rule choose supported, unsupported, uncertain or not applicable. Supported means the specific static condition is present, not that a deployed vulnerability exists. Unsupported means the condition is absent. Provide source line evidence, reason, confidence (high/medium/low), and deployment applicability separately. Leave nothing blank at submission; explain uncertainty. Test fixtures and sample credentials need explicit applicability review.

Submit forms separately. A third person adjudicates disagreements after both forms are locked. The empty adjudication template does not contain either reviewer's decisions. Never turn uncertain or inapplicable records into positive labels. No field recall can be claimed without reviewed, applicable no-finding samples and defensible positive labels. Stratified sampling is deliberately enriched; it is not an estimate of natural repository prevalence.

Expected labels remain unknown until adjudication. Do not run accuracy metrics on fabricated decisions. Do not reuse this dataset for tuning while retaining its independent designation.
