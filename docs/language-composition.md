# Repository language composition

The README chart is generated from the current `main` commit. It walks Git's committed tree and uses the pinned GitHub Linguist image to classify each tracked blob. The JSON inventory records the path, byte count, detected language, MIME type, and Linguist generated/vendor flags for every file. Its `generated_at` value is the source commit time, keeping output reproducible for a given commit. Linguist's `Open Policy Agent` label is shown as `Rego`; `.v` and `.vh` HDL files are kept as `Verilog`, while `.sv` and `.svh` files are kept as `SystemVerilog`.

Language percentages are byte-weighted: a language's bytes divided by the total bytes of classified textual-language files. Every detected language is listed, including documentation, configuration, build files, and generated or vendored text. There is intentionally no `Other` category and no top-N cutoff.

Tracked textual files with no Linguist language are listed in `unclassified_files` and do not affect percentages. Binary and other non-text files are listed in `non_language_assets` and also do not affect percentages. The generator reads the selected Git commit, not untracked or modified working-tree files.

To regenerate locally, install Docker Desktop, then run:

```powershell
python scripts/generate_language_composition.py --ref main
```

The script runs the official Linguist container pinned by digest with network access disabled. It writes `assets/generated/language-composition.svg` and `assets/generated/language-composition.json`. The `language-composition` workflow refreshes these files from `main` and publishes them to the `generated-metrics` branch.
