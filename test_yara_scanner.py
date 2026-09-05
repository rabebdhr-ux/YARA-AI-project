"""
Focused unit tests for yara_scanner.py:
- YARA match handling (evidence/strings must be preserved, not invented)
- YARA no-match handling
- missing-file / no-rules edge cases

Run with:
    python -m unittest test_yara_scanner -v
"""

import os
import tempfile
import unittest

from yara_scanner import YARAScanner


class TestYaraScanner(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scanner = YARAScanner("yara_rules")

    def test_rules_loaded(self):
        self.assertIsNotNone(self.scanner.rules)

    def test_match_preserves_real_evidence(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("some text\nTEST_MALWARE_INDICATOR\nmore text\n")
            path = f.name

        try:
            result = self.scanner.scan_file(path)

            self.assertEqual(result["total_matches"], 1)
            self.assertEqual(len(result["matches"]), 1)

            match = result["matches"][0]
            self.assertEqual(match["rule"], "Test_Malware_Indicator")
            self.assertEqual(match["namespace"], "test_rules")

            # The scanner must expose the real matched string data,
            # not leave it empty when YARA actually provides it.
            self.assertTrue(len(match["strings"]) >= 1)
            string_match = match["strings"][0]
            self.assertEqual(string_match["identifier"], "$test")
            self.assertEqual(string_match["data"], "TEST_MALWARE_INDICATOR")
            self.assertIsInstance(string_match["offset"], int)
        finally:
            os.unlink(path)

    def test_no_match_on_benign_content(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("nothing suspicious here at all\n")
            path = f.name

        try:
            result = self.scanner.scan_file(path)

            self.assertEqual(result["total_matches"], 0)
            self.assertEqual(result["matches"], [])
            self.assertEqual(result["errors"], [])
        finally:
            os.unlink(path)

    def test_missing_file_reports_error_without_crashing(self):
        result = self.scanner.scan_file("this_file_does_not_exist.txt")

        self.assertEqual(result["matches"], [])
        self.assertTrue(len(result["errors"]) >= 1)

    def test_no_rules_loaded_reports_error_without_crashing(self):
        empty_dir = tempfile.mkdtemp()
        scanner = YARAScanner(empty_dir)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("irrelevant content\n")
            path = f.name

        try:
            result = scanner.scan_file(path)
            self.assertEqual(result["matches"], [])
            self.assertTrue(len(result["errors"]) >= 1)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
