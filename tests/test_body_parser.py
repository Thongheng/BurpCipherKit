from __future__ import print_function

import unittest

from core.body_parser import parse_body, serialize_body


class UrlEncodedSerializationTests(unittest.TestCase):
    def test_encodes_changed_and_added_values_without_corrupting_existing_pairs(self):
        original = "name=A%26B&note=hello+world&dup=1&dup=2"
        data = parse_body(original, "application/x-www-form-urlencoded")
        data["note"] = "hello earth"
        data["hash"] = "x+y&z"

        result = serialize_body(data, original, "application/x-www-form-urlencoded")

        self.assertIn("name=A%26B", result)
        self.assertIn("note=hello+earth", result)
        self.assertIn("dup=1&dup=2", result)
        self.assertIn("hash=x%2By%26z", result)


class MultipartSerializationTests(unittest.TestCase):
    def test_preserves_file_part_headers_and_body_when_adding_hash(self):
        original = (
            "--b\r\n"
            "Content-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "hello file\r\n"
            "--b\r\n"
            "Content-Disposition: form-data; name=\"note\"\r\n\r\n"
            "old note\r\n"
            "--b--\r\n"
        )
        data = parse_body(original, "multipart/form-data; boundary=b")
        data["note"] = "new note"
        data["hash"] = "abc123"

        result = serialize_body(data, original, "multipart/form-data; boundary=b")

        self.assertIn('name="upload"; filename="a.txt"', result)
        self.assertIn("Content-Type: text/plain", result)
        self.assertIn("hello file", result)
        self.assertIn('name="note"\r\n\r\nnew note', result)
        self.assertIn('name="hash"\r\n\r\nabc123', result)
        self.assertEqual(1, result.count("--b--"))


if __name__ == "__main__":
    unittest.main()
