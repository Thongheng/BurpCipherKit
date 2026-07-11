from __future__ import print_function

import unittest

from core.key_finder import (
    compare_generated_hash, format_hash_comparison, strip_hash_comparison,
    should_render_hash_output, find_key_orders,
)


class KeyOrderSearchTests(unittest.TestCase):
    def test_finds_orders_without_mutating_input(self):
        fields = {"first": "ab", "second": "cd"}
        matches, visited, capped = find_key_orders(fields, "abcd")

        self.assertEqual([("first", "second")], matches)
        self.assertGreater(visited, 0)
        self.assertFalse(capped)
        self.assertEqual({"first": "ab", "second": "cd"}, fields)

    def test_reports_cap_for_large_search(self):
        fields = dict(("k%d" % i, "a") for i in range(10))
        matches, visited, capped = find_key_orders(fields, "aaaaaaaaab", max_visited=20)

        self.assertEqual([], matches)
        self.assertEqual(20, visited)
        self.assertTrue(capped)

class CompareGeneratedHashTests(unittest.TestCase):
    def test_compares_case_insensitively(self):
        self.assertEqual("valid", compare_generated_hash("ABCD", {"hash": "abcd"}, "hash"))

    def test_reports_invalid_hash(self):
        self.assertEqual("invalid", compare_generated_hash("new", {"signature": "old"}, "signature"))

    def test_reports_absent_reference_hash(self):
        self.assertEqual("missing", compare_generated_hash("new", {"id": "1"}, "hash"))

    def test_reports_error_result_without_comparing(self):
        self.assertEqual("error", compare_generated_hash("Error: failed", {"hash": "failed"}, "hash"))

    def test_formats_match_inside_hash_output(self):
        self.assertEqual("abcd (Match)", format_hash_comparison("abcd", "valid"))

    def test_formats_not_match_inside_hash_output(self):
        self.assertEqual("abcd (Not Match)", format_hash_comparison("abcd", "invalid"))

    def test_missing_reference_keeps_plain_hash(self):
        self.assertEqual("abcd", format_hash_comparison("abcd", "missing"))

    def test_strips_stale_comparison_suffix(self):
        self.assertEqual("abcd", strip_hash_comparison("abcd (Match)"))
        self.assertEqual("abcd", strip_hash_comparison("abcd (Not Match)"))

    def test_comparison_forces_hash_output_even_in_crypto_mode(self):
        self.assertTrue(should_render_hash_output(True, True))
        self.assertFalse(should_render_hash_output(False, True))
if __name__ == "__main__":
    unittest.main()
