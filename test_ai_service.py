"""
Focused unit tests for ai_service.py:
- robust JSON extraction from various LLM response shapes
- AI result normalization
- generate_yara_report() end-to-end with the NVIDIA client mocked out,
  covering match / no-match / malformed-JSON / API-error cases.

Run with:
    python -m unittest test_ai_service -v
"""

import json
import unittest
from unittest.mock import patch, MagicMock

from ai_service import (
    extract_json_object,
    normalize_ai_result,
    generate_yara_report,
)


class TestExtractJsonObject(unittest.TestCase):

    def test_pure_json(self):
        content = '{"summary": "ok", "reasons": []}'
        result = extract_json_object(content)
        self.assertEqual(result["summary"], "ok")

    def test_json_with_surrounding_whitespace(self):
        content = "\n\n   {\"summary\": \"ok\"}   \n"
        result = extract_json_object(content)
        self.assertEqual(result["summary"], "ok")

    def test_json_in_markdown_fence(self):
        content = "```json\n{\"summary\": \"ok\"}\n```"
        result = extract_json_object(content)
        self.assertEqual(result["summary"], "ok")

    def test_json_in_plain_fence(self):
        content = "```\n{\"summary\": \"ok\"}\n```"
        result = extract_json_object(content)
        self.assertEqual(result["summary"], "ok")

    def test_json_embedded_in_explanatory_text(self):
        content = (
            "Sure, here is the analysis: "
            '{"summary": "ok", "evidence": ["a"]} '
            "Let me know if you need anything else."
        )
        result = extract_json_object(content)
        self.assertEqual(result["summary"], "ok")
        self.assertEqual(result["evidence"], ["a"])

    def test_braces_inside_string_values_do_not_break_parsing(self):
        content = (
            'Some text before {"summary": "this mentions {curly} braces"} '
            "and some trailing text with a } stray brace."
        )
        result = extract_json_object(content)
        self.assertEqual(result["summary"], "this mentions {curly} braces")

    def test_empty_response_raises(self):
        with self.assertRaises(ValueError):
            extract_json_object("")

    def test_none_response_raises(self):
        with self.assertRaises(ValueError):
            extract_json_object(None)

    def test_no_json_present_raises(self):
        with self.assertRaises(ValueError):
            extract_json_object("this response has no json at all")


class TestNormalizeAiResult(unittest.TestCase):

    def test_fills_missing_fields_with_defaults(self):
        normalized = normalize_ai_result({})
        self.assertEqual(normalized["summary"], "No AI summary available.")
        self.assertEqual(normalized["reasons"], [])
        self.assertEqual(normalized["evidence"], [])
        self.assertEqual(normalized["recommendations"], [])
        self.assertFalse(normalized["processing"])
        self.assertIsNone(normalized["error"])

    def test_coerces_non_list_fields_to_single_item_lists(self):
        normalized = normalize_ai_result({
            "reasons": "a single reason string",
            "evidence": 42,
            "recommendations": None,
        })
        self.assertEqual(normalized["reasons"], ["a single reason string"])
        self.assertEqual(normalized["evidence"], ["42"])
        self.assertEqual(normalized["recommendations"], ["None"])

    def test_preserves_valid_list_fields(self):
        normalized = normalize_ai_result({
            "reasons": ["r1", "r2"],
            "evidence": ["e1"],
            "recommendations": ["rec1", "rec2"],
        })
        self.assertEqual(normalized["reasons"], ["r1", "r2"])
        self.assertEqual(normalized["evidence"], ["e1"])
        self.assertEqual(normalized["recommendations"], ["rec1", "rec2"])

    def test_non_dict_input_raises(self):
        with self.assertRaises(ValueError):
            normalize_ai_result(["not", "a", "dict"])


def _mock_openai_response(content):
    message = MagicMock()
    message.content = content
    choice = MagicMock()
    choice.message = message
    response = MagicMock()
    response.choices = [choice]
    return response


class TestGenerateYaraReport(unittest.TestCase):

    @patch("ai_service.client.chat.completions.create")
    def test_match_case_returns_normalized_result(self, mock_create):
        ai_json = {
            "summary": "Matched Test_Malware_Indicator.",
            "reasons": ["The string $test matched."],
            "evidence": ["YARA rule: Test_Malware_Indicator"],
            "risk_assessment": "Consistent with MEDIUM risk.",
            "recommendations": ["Investigate further."],
        }
        mock_create.return_value = _mock_openai_response(
            json.dumps(ai_json)
        )

        yara_result = {
            "match": True,
            "matches": [{
                "rule": "Test_Malware_Indicator",
                "namespace": "test_rules",
                "tags": [],
                "strings": [
                    {"identifier": "$test", "data": "TEST_MALWARE_INDICATOR", "offset": 42}
                ],
            }],
            "risk_level": "MEDIUM",
            "risk_score": 30,
        }

        result = generate_yara_report(yara_result, scan_id="abcd1234")

        self.assertIsNone(result["error"])
        self.assertFalse(result["processing"])
        self.assertEqual(result["summary"], ai_json["summary"])
        mock_create.assert_called_once()

    @patch("ai_service.client.chat.completions.create")
    def test_no_match_case_selects_no_match_prompt(self, mock_create):
        ai_json = {
            "summary": "No rule matched.",
            "reasons": ["No configured rule triggered."],
            "evidence": ["YARA matches: 0"],
            "risk_assessment": "Consistent with SAFE risk.",
            "recommendations": ["Consider additional scanning."],
        }
        mock_create.return_value = _mock_openai_response(
            json.dumps(ai_json)
        )

        yara_result = {"match": False, "matches": [], "risk_level": "SAFE", "risk_score": 0}

        result = generate_yara_report(yara_result)

        self.assertFalse(result["processing"])
        self.assertEqual(result["summary"], ai_json["summary"])

        sent_prompt = mock_create.call_args.kwargs["messages"][1]["content"]
        self.assertIn("NO MATCH", sent_prompt)

    @patch("ai_service.client.chat.completions.create")
    def test_malformed_json_does_not_crash_and_reports_error(self, mock_create):
        mock_create.return_value = _mock_openai_response(
            "I'm sorry, I cannot comply with that request."
        )

        result = generate_yara_report({"match": False})

        self.assertIsNotNone(result["error"])
        self.assertEqual(result["summary"], "AI analysis could not be generated.")
        self.assertFalse(result["processing"])

    @patch("ai_service.client.chat.completions.create")
    def test_api_error_does_not_crash_and_reports_error(self, mock_create):
        mock_create.side_effect = ConnectionError("NVIDIA endpoint unreachable")

        result = generate_yara_report({"match": True, "matches": []})

        self.assertIsNotNone(result["error"])
        self.assertIn("NVIDIA API error", result["error"])
        self.assertFalse(result["processing"])

    @patch("ai_service.client.chat.completions.create")
    def test_no_choices_returned_is_handled(self, mock_create):
        response = MagicMock()
        response.choices = []
        mock_create.return_value = response

        result = generate_yara_report({"match": False})

        self.assertIsNotNone(result["error"])
        self.assertFalse(result["processing"])


if __name__ == "__main__":
    unittest.main()
