import unittest

from scripts.prepare_independent_review import select_paths


class ReviewSelectionTests(unittest.TestCase):
    def test_deterministic_selection_and_strata(self):
        entries = [{"path": f"src/file{i}.c", "type": "blob"} for i in range(30)]
        entries.extend({"path": f"cert/key{i}.pem", "type": "blob"} for i in range(12))
        selected = select_paths(entries, "frozen-seed")
        self.assertEqual(selected, select_paths(list(reversed(entries)), "frozen-seed"))
        self.assertEqual(24, len(selected))
        self.assertEqual(8, sum(p["path"].endswith(".pem") for p in selected))
        self.assertNotEqual(selected, select_paths(entries, "different-seed"))

    def test_upstream_paths_cannot_escape_cache(self):
        for path in ("../escape.c", "/absolute.c", "dir\\escape.c"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                select_paths([{"path": path, "type": "blob"}], "seed")
