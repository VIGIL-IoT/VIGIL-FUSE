# FUSE rights and distribution review packet

**Prepared:** 2026-11-11

**Status:** Open. License version 1.1 and matching package metadata were drafted on 2026-11-04 to permit unmodified official package distribution through PyPI and compatible mirrors. FUSE 0.3.0 has since been published on [PyPI](https://pypi.org/project/vigil-fuse/), following the owner's 2026-11-11 release decision. The text has not been reviewed by qualified counsel, and PyPI has not confirmed that FUSE fits its Acceptable Use Policy. This packet is not a legal determination.

## Current repository facts

- The root `LICENSE` declares the custom VIGIL-FUSE Restricted Use License, version 1.1, with VIGIL-IoT named as copyright holder.
- The license permits personal, research, internal, and commercial use. It permits private modification and use of scan outputs. It grants a narrow exception for unmodified official packages distributed through PyPI and compatible mirrors. Other registry distribution and public sharing of modifications remain restricted.
- `pyproject.toml` declares `LicenseRef-VIGIL-FUSE-PyPI-Restricted-Use` and includes the root license in built artifacts.
- Repository history includes earlier MIT license text. The current license does not revoke permissions already granted to copies received under the earlier terms.
- `CONTRIBUTING.md` pauses public code contributions while ownership and contribution terms are unresolved.
- PyPI Support issue [#12999](https://github.com/pypi/support/issues/12999) requests project-specific policy and license-term guidance. It had only an automated acknowledgement as of 2026-11-11. The owner authorized the initial 0.3.0 PyPI attempt before a staff response. This is not PyPI approval.
- The project owner stated a preference for allowing commercial use while restricting copying and redistribution. That preference is recorded here for review. The repository's listed copyright holder, authorship, and legal authority to grant permissions still need confirmation.

## Questions for the rights holder and counsel

### Ownership and authority

- Who created each part of the package, documentation, website, figures, icons, and test fixtures?
- Were any contributions created under employment, school, grant, contract, or other terms that assign or limit rights?
- Does each person or organization named as a rights holder have authority to grant the permissions in the current license?
- Are any trademarks, project names, logos, or third-party visual assets included, and what permission applies to each?

### License history and copies

- What permissions were granted by each public license state and release tag?
- Which commits, tags, archives, forks, and downstream copies contain earlier MIT terms?
- How should current notices describe the continuing rights attached to those earlier copies?
- Does the current custom license express the intended rules for use, private modification, hosted service use, reporting outputs, attribution, and termination?

### Third-party material and contributions

- Inventory copied or adapted code, examples, test data, generated files, fonts, images, and documentation excerpts.
- Record each item's source, version or commit, license, notice requirements, and whether redistribution is permitted.
- Confirm that generated scan reports do not include third-party source text or sensitive data that should not be redistributed.
- Decide whether to continue the no-public-code-contribution policy or adopt a written contributor agreement and contribution license.

### Distribution channels

- Review the current terms for every proposed distribution method, including GitHub Release assets, package registries, container registries, source archives, and hosted installation instructions.
- Confirm whether a channel's mirror, cache, install, and user-copy terms are compatible with the current redistribution restriction.
- Confirm whether package metadata accurately communicates the custom terms and whether a channel accepts those terms.
- The license contains a PyPI-specific grant. The owner authorized the first 0.3.0 publication attempt before project-specific PyPI Support and qualified legal review were complete. Record the outcome, and do not treat a successful upload as PyPI policy clearance or legal review.

## Evidence to collect

| Evidence | Owner or source | Collected | Reviewed |
| --- | --- | --- | --- |
| Authorship and rights-holder record for source and documentation | Project owner | No | No |
| Employment, school, grant, or contract assignment check | Project owner | No | No |
| Prior license and release history review | Project owner and counsel | Partial, see repository history | No |
| Third-party code and asset inventory with notices | Project maintainer | No | No |
| Channel terms and intended distribution methods | Project owner and counsel | Partial, see release process | No |
| Written decision on contributions and derivatives | Project owner and counsel | No | No |
| Reviewed license text and matching package metadata | Qualified counsel and maintainer | Draft v1.1 and metadata updated on 2026-11-04 | No |
| PyPI Acceptable Use Policy decision for a defensive vulnerability-analysis CLI | PyPI Support issue [#12999](https://github.com/pypi/support/issues/12999) and project owner | Open, no staff response as of 2026-11-11 | No |
| Release approver and permission request route | Project owner | No | No |

## Release decision record

Complete this section after review. Do not infer approval from a successful build, tag, GitHub repository setting, or package metadata validation.

- Confirmed rights holder:
- Counsel or qualified reviewer and review date:
- Approved license and version:
- Allowed distribution channels:
- Allowed derivative and contribution policy:
- Required third-party notices:
- Release approver:
- Permission request contact:
- Conditions or exclusions:

## Current release gate

The owner's first PyPI publication attempt for version 0.3.0 succeeded while policy and legal reviews remained open. This does not mark the review complete or award a maturity point. Future releases and other distribution channels require a separate recorded decision. Governance remains at 7/10 until the rights, channel, and enforcement decisions are reviewed and documented.
