from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from vigil_fuse.support import support_matrix


class SupportMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        support_matrix.cache_clear()

    def tearDown(self) -> None:
        support_matrix.cache_clear()

    def test_non_object_resource_is_rejected(self) -> None:
        resource_package = Mock()
        resource_package.joinpath.return_value.read_text.return_value = "[]"

        with patch("vigil_fuse.support.files", return_value=resource_package):
            with self.assertRaisesRegex(ValueError, "must be a JSON object"):
                support_matrix()

    def test_frontier_capabilities_are_experimental_and_disclose_limits(self) -> None:
        capabilities = {item["id"]: item for item in support_matrix()["capabilities"]}
        for name in (
            "cyber-physical.reachability",
            "flight.cfe-bus",
            "flight.radiation-indicators",
            "hardware.digital-twin",
        ):
            self.assertEqual("experimental", capabilities[name]["label"])
            self.assertTrue(capabilities[name]["limitations"])
