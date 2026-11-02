# AI skills and specialist tools reference

This register records the specialist tools named by the repository engineering prompt, whether they are available in this Codex session, and whether they were used for FUSE. Availability here does not mean a tool is a FUSE runtime dependency. Local repository code remains the source of truth for claims about FUSE behavior.

## Used for FUSE

| Skill or tool | Source | Availability | Use in this repository | Artifacts and validation |
| --- | --- | --- | --- | --- |
| Anatomy | [wheresryan22/anatomy](https://github.com/wheresryan22/anatomy) | Installed as a Codex skill | Used for the conceptual finding model. The figure explains severity, confidence, applicability, and validation as independent fields. It does not depict a physical FUSE device. It is retained because the new 2D figure covers execution boundaries, a different concept | `docs/figures/fuse-finding-model.svg`, its light-theme counterpart, and `site/diagrams/fuse-finding-model.html`. The previous repository audit records dark and light rendering review |
| Taste Skill | [Leonxlnx/taste-skill](https://github.com/leonxlnx/taste-skill) | A frontend design equivalent is available in this session | Used for the FUSE website restyle, with the local NOEMA checkout as the style reference and FUSE colors and content preserved | `site/index.html`, `site/styles.css`, and `site/script.js`. Desktop, tablet, mobile, dark, and light previews were reviewed |
| Diagram Design | [cathrynlavery/diagram-design](https://github.com/cathrynlavery/diagram-design) | Installed as a Codex skill | Used for a focused 2D trust-boundary view. Mermaid remains the editable implementation reference, while this figure clarifies project input and optional analyzer runtime boundaries | `docs/diagrams/fuse-trust-boundaries.html` and `docs/figures/fuse-trust-boundaries.svg`, integrated in `README.md` and `docs/architecture.md`. The skill self-check, SVG XML parsing, and light/dark browser renders passed |
| Crawl4AI | [unclecode/crawl4ai](https://github.com/unclecode/crawl4ai) | Python package 0.9.5 is installed in the working environment | Existing maturity research used it to collect official NIST, Docker, OSI, GitHub, Python Packaging, and Semgrep sources. This pass used it only to verify prompt-listed public skill repository pages, not to inspect local FUSE or NOEMA source | See `docs/research/maturity-100-closure-plan-2026-11-02.md`. This pass fetched the Anatomy, Diagram Design, Taste Skill, and ManimGX pages. Remaining GitHub pages timed out in Crawl4AI, so their contents are not treated as verified |

## Referenced writing skills

The pasted prompt names the following README and technical-writing repositories. Their stated purpose and activation conditions are recorded here. Crawl4AI timed out while opening these GitHub pages during this pass, so the owner/repository strings below are references copied from the prompt, not independent claims that the pages are currently available. No missing URL is inferred.

| Skill reference from prompt | Purpose and trigger | Availability and use |
| --- | --- | --- |
| `adewale/good-readme` | Evidence-based README audit and composition for a project repository | Not available as a local skill. Equivalent repository review, README updates, and link validation were used |
| `indubitably-ai/readme-writing` | README organization, navigation, examples, and presentation | Not available as a local skill. Equivalent repository documentation review was used |
| `JayRHa/agent-skills` `readme-generator` | README structure, badges, quick start, usage, configuration, and examples | Not available as a local skill. The README was written against the current CLI and validated locally |
| `JayRHa/agent-skills` `technical-writer` | Precise technical guides, API references, release notes, and tutorials | Not available as a local skill. The guide and current implementation were checked with repository documentation validation |
| `riekelt/technical-writer` | Evidence-backed technical writing that distinguishes implemented and planned behavior | Not available as a local skill. FUSE docs use implementation and test evidence and label limitations |
| `Shpigford/readme` | Comprehensive README guidance when a longer project overview is useful | Not available as a local skill. The existing README was retained and selectively improved |
| `matt-riley/writing-and-editing` | Final editorial review for clarity, structure, consistency, and tone | Not available as a local skill. A project-specific editorial review was applied |
| `boffti/github-profile-readme` | GitHub profile README conventions | Not applicable. FUSE is a project repository, not a GitHub profile README |

## Referenced visualization and hardware tools

| Skill or tool | Repository reference | Trigger and fit for FUSE | Availability and use |
| --- | --- | --- | --- |
| ManimGX | [academa-labs/manimgx](https://github.com/academa-labs/manimgx) | Use when time-dependent signal, state, or algorithm behavior benefits from animation | Not installed and not used. FUSE's static scan stages and finding model are explained by existing diagrams |
| KiCad Happy | [aklofas/kicad-happy](https://github.com/aklofas/kicad-happy) | PCB-specific editing or review workflow | Not available and not used. FUSE reads selected KiCad XML data and does not author boards |
| KiStack | [American-Embedded/KiStack](https://github.com/American-Embedded/KiStack) | KiCad board design and PCB workflow | Not available and not used. Board authoring is outside this repository's purpose |
| AI-PCB-layout | [ChengminLi/AI-PCB-layout](https://github.com/ChengminLi/AI-PCB-layout) | PCB placement and routing assistance | Not available and not used. FUSE does not generate PCB layouts |
| kicad-mcp-pro | [oaslananka/kicad-mcp-pro](https://github.com/oaslananka/kicad-mcp-pro) | MCP-based KiCad project interaction | Not available and not used. FUSE does not edit a KiCad project |
| circuit-skills | [punkfab/circuit-skills](https://github.com/punkfab/circuit-skills) | Circuit and PCB design tasks | Not available and not used. No FUSE-owned circuit exists to validate |
| Matplotlib, Plotly, and R with ggplot2 | Named as optional scientific visualization tools in the prompt | Use for measured quantitative data when they improve statistical or scientific communication | No new plots were needed. Existing FUSE scan figures are generated from checked-in data by repository scripts |

## Verified source pages

These page checks were performed with Crawl4AI 0.9.5 on 2026-11-02. A successful fetch verifies that the page was retrievable and that its repository identity and description matched the referenced tool. It does not establish code quality, safety, compatibility, or suitability for adoption.

| Source | Type and authority | Decision supported | Limitation |
| --- | --- | --- | --- |
| [Anatomy](https://github.com/wheresryan22/anatomy) | Upstream project repository | Preserve the existing finding-model illustration and document its actual use | Repository page only; no new figure was generated in this pass |
| [Diagram Design](https://github.com/cathrynlavery/diagram-design) | Upstream project repository | Use a distinct trust-boundary figure without replacing detailed Mermaid architecture | Page metadata and description only; implementation claims come from local source, tests, and `docs/threat-model.md` |
| [Taste Skill](https://github.com/leonxlnx/taste-skill) | Upstream project repository | Record the visual skill used for the website restyle | The local NOEMA source remained the page-style reference |
| [ManimGX](https://github.com/academa-labs/manimgx) | Upstream project repository | Record the referenced animation tool and why no animation was added | Page metadata and description only |

## Research and validation notes

- The local NOEMA source checkout was used to understand the website reference. Crawl4AI was not used to inspect either local repository.
- Crawl4AI 0.9.5 successfully retrieved the Anatomy, Diagram Design, Taste Skill, and ManimGX GitHub pages. Other prompt-listed GitHub pages timed out during this pass. Their references are retained from the prompt and their contents are marked unverified.
- Tools named by the prompt are not automatically adopted. They are used when they add a concrete capability to FUSE and have a verifiable validation path.
- No third-party skill source code was copied into FUSE as part of this audit. The existing vendored Anatomy kit retains its notice and license under `scripts/vendor/anatomy/`.
