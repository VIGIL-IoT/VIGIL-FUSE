from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vigil_fuse.input_types import is_sbom_file


class InputTypeTests(unittest.TestCase):
    def test_detects_cyclonedx_and_spdx_from_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cdx = root / "inventory.json"
            spdx = root / "manifest.json"
            cdx.write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")
            spdx.write_text('{"spdxVersion":"SPDX-2.3","packages":[]}', encoding="utf-8")
            self.assertTrue(is_sbom_file(cdx))
            self.assertTrue(is_sbom_file(spdx))

    def test_does_not_classify_arbitrary_json_as_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "settings.json"
            source.write_text('{"device":{"enabled":true}}', encoding="utf-8")
            self.assertFalse(is_sbom_file(source))

    def test_recognizes_spdx_tag_value_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "inventory.spdx"
            source.write_text("SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n", encoding="utf-8")
            self.assertTrue(is_sbom_file(source))

    def test_sbom_detection_reads_no_more_than_the_configured_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "bom.json"
            source.write_bytes(b'{"bomFormat":"CycloneDX"}')
            with patch("vigil_fuse.input_types.MAX_SBOM_DETECTION_BYTES", 8):
                self.assertFalse(is_sbom_file(source))


if __name__ == "__main__":
    unittest.main()
