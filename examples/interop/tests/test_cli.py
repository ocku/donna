"""The lab must reject a successful CLI exit with the wrong DNS answer."""

import copy
import json
import unittest

from support.cli import EXPECTED_IPV4, QUERY_NAME, check_response


class CliResponseTests(unittest.TestCase):
    def setUp(self):
        self.response = {
            "status": "Ok",
            "questions": [{"name": QUERY_NAME, "type": "A", "class_code": 1}],
            "answers": [
                {"name": QUERY_NAME, "type": "A", "class": "IN", "data": EXPECTED_IPV4}
            ],
        }

    def test_expected_fixture_is_accepted(self):
        self.assertEqual(check_response(json.dumps(self.response)), self.response)

    def test_wrong_status_or_question_is_rejected(self):
        for field, value in [
            ("status", "NameError"),
            ("questions", []),
            (
                "questions",
                [{"name": "unrelated.example.", "type": "A", "class_code": 1}],
            ),
        ]:
            with self.subTest(field=field, value=value):
                response = copy.deepcopy(self.response)
                response[field] = value
                with self.assertRaises(RuntimeError):
                    check_response(json.dumps(response))

    def test_wrong_owner_type_class_and_address_are_rejected(self):
        for field, value in [
            ("name", "unrelated.example."),
            ("type", "AAAA"),
            ("class", "CH"),
            ("data", "192.0.2.99"),
        ]:
            with self.subTest(field=field):
                response = copy.deepcopy(self.response)
                response["answers"][0][field] = value
                with self.assertRaises(RuntimeError):
                    check_response(json.dumps(response))

    def test_duplicate_and_unsolicited_answers_are_rejected(self):
        for extra in [
            self.response["answers"][0],
            {"name": QUERY_NAME, "type": "A", "class": "IN", "data": "192.0.2.99"},
        ]:
            with self.subTest(extra=extra):
                response = copy.deepcopy(self.response)
                response["answers"].append(extra)
                with self.assertRaises(RuntimeError):
                    check_response(json.dumps(response))

    def test_empty_answer_is_rejected(self):
        self.response["answers"] = []
        with self.assertRaises(RuntimeError):
            check_response(json.dumps(self.response))


if __name__ == "__main__":
    unittest.main()
