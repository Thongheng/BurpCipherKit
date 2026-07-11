from __future__ import print_function

import unittest

from core.app_setting_manager import AppSettingManager, mask_secret, merge_custom_data


class SecretMaskingTests(unittest.TestCase):
    def test_masks_secret_but_keeps_last_four_characters(self):
        self.assertEqual("********3456", mask_secret("super_secret_3456"))

    def test_masks_short_secret_without_exposing_value(self):
        self.assertEqual("********", mask_secret("abc"))


class CustomDataMergeTests(unittest.TestCase):
    def test_endpoint_values_override_shared_values_without_dropping_other_keys(self):
        self.assertEqual(
            {"client": "mobile", "token": "endpoint-token"},
            merge_custom_data(
                {"client": "mobile", "token": "shared-token"},
                {"token": "endpoint-token"},
            ),
        )


class ResolveForUrlTests(unittest.TestCase):
    def setUp(self):
        self.manager = AppSettingManager.__new__(AppSettingManager)
        self.manager.app_settings = {
            "Matched": {"endpoints": {"/matched": {"keys_order": "id"}}},
            "ABA Mobile": {"algorithm": "SHA-1", "endpoints": {}},
        }

    def test_uses_default_app_when_url_has_no_match(self):
        name, app, pattern, endpoint = self.manager.resolve_for_url(
            "/unknown", "ABA Mobile"
        )

        self.assertEqual("ABA Mobile", name)
        self.assertEqual("SHA-1", app["algorithm"])
        self.assertEqual("(default load)", pattern)
        self.assertIsNone(endpoint)

    def test_url_match_takes_precedence_over_default(self):
        name, _, pattern, endpoint = self.manager.resolve_for_url(
            "/matched", "ABA Mobile"
        )

        self.assertEqual("Matched", name)
        self.assertEqual("/matched", pattern)
        self.assertEqual("id", endpoint["keys_order"])

    def test_selects_most_specific_overlapping_pattern(self):
        self.manager.app_settings = {
            "Broad": {"endpoints": {"/api/v3/*": {"keys_order": "broad"}}},
            "Specific": {"endpoints": {"/api/v3/orders/*": {"keys_order": "specific"}}},
            "Exact": {"endpoints": {"/api/v3/orders/42": {"keys_order": "exact"}}},
        }

        exact = self.manager.find_by_url("/api/v3/orders/42")
        specific = self.manager.find_by_url("/api/v3/orders/7")

        self.assertEqual("Exact", exact[0])
        self.assertEqual("exact", exact[3]["keys_order"])
        self.assertEqual("Specific", specific[0])
        self.assertEqual("specific", specific[3]["keys_order"])

    def test_none_default_returns_no_setting(self):
        self.assertEqual(
            (None, None, None, None),
            self.manager.resolve_for_url("/unknown", "(none)")
        )

    def test_selected_app_uses_most_specific_endpoint_match(self):
        self.manager.app_settings = {
            "ABA Mobile": {
                "endpoints": {
                    "/api/v3/*": {"keys_order": "broad"},
                    "/api/v3/pay": {"keys_order": "exact"},
                }
            }
        }

        pattern, endpoint = self.manager.find_endpoint_in_app(
            "ABA Mobile", "/api/v3/pay"
        )

        self.assertEqual("/api/v3/pay", pattern)
        self.assertEqual("exact", endpoint["keys_order"])

    def test_selected_app_returns_no_endpoint_for_unmatched_url(self):
        pattern, endpoint = self.manager.find_endpoint_in_app("ABA Mobile", "/unmatched")

        self.assertIsNone(pattern)
        self.assertIsNone(endpoint)


class SaveAppTests(unittest.TestCase):
    def test_partial_update_preserves_default_kf_key(self):
        manager = AppSettingManager.__new__(AppSettingManager)
        manager.app_settings = {
            "ABA Mobile": {
                "default_kf_key": "token",
                "endpoints": {"/api": {"keys_order": "id"}},
            }
        }
        manager.save = lambda: True

        manager.save_app("ABA Mobile", {"algorithm": "SHA-1"})

        self.assertEqual("token", manager.get_app("ABA Mobile")["default_kf_key"])
        self.assertIn("/api", manager.get_app("ABA Mobile")["endpoints"])


if __name__ == "__main__":
    unittest.main()
