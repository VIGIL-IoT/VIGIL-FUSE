from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from scripts.build_ghidra_late_string_fixtures import (
    KINDS,
    LIMIT_REFERENCE_COUNT,
    ORDINARY_STRING_COUNT,
    build,
    render_source,
)


class GhidraLateStringFixtureTests(unittest.TestCase):
    def test_generates_late_referenced_secure_and_unreferenced_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build(root)
            self.assertTrue((root / "layout.ld").is_file())
            self.assertEqual({"layout.ld"}, {path.name for path in root.iterdir()})
            for kind in KINDS:
                with self.subTest(kind=kind):
                    source = render_source(kind)
                    ordinary_declarations = [
                        line
                        for line in source.splitlines()
                        if "ordinary_" in line and "[] =" in line
                    ]
                    self.assertEqual(ORDINARY_STRING_COUNT, len(ordinary_declarations))
                    self.assertLess(
                        source.index("ordinary_1599[]"), source.index("endpoint_http[]")
                    )
                    self.assertIn("endpoint_http[]", source)
                    self.assertIn("endpoint_mqtt[]", source)
                    if kind == "unreferenced":
                        self.assertNotIn("fuse_sink = endpoint_http", source)
                        self.assertNotIn("fuse_sink = endpoint_mqtt", source)
                    else:
                        self.assertIn("fuse_sink = endpoint_http", source)
                        self.assertIn("fuse_sink = endpoint_mqtt", source)
                    if kind == "limited":
                        self.assertEqual(
                            LIMIT_REFERENCE_COUNT,
                            source.count("fuse_sink = endpoint_http;"),
                        )


if __name__ == "__main__":
    unittest.main()
