from __future__ import print_function

import unittest

from core.utils import _safe_text


class SafeTextTests(unittest.TestCase):
    def test_preserves_unicode_divider(self):
        divider = u"\u2500" * 52

        self.assertEqual(divider, _safe_text(divider))

    def test_decodes_utf8_bytes(self):
        self.assertEqual(u"សួស្តី", _safe_text(u"សួស្តី".encode("utf-8")))


if __name__ == "__main__":
    unittest.main()
