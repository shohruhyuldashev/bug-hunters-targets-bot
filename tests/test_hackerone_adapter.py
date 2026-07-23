import unittest

from adapters.hackerone import HackerOneAdapter
from compare import deduplicate_assets
from models import TargetAsset


class HackerOneAdapterParserTests(unittest.TestCase):
    def setUp(self):
        self.adapter = HackerOneAdapter(
            endpoint="https://example.test/scope",
            program_name="Example Program",
            credential_identifier=None,
            credential_token=None,
            timeout_seconds=10,
        )

    def test_reads_json_api_asset(self):
        assets = self.adapter._json_assets(
            {"data": [{"attributes": {"asset_identifier": "api.example.test", "asset_type": "API"}}]}
        )
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].identifier, "api.example.test")
        self.assertEqual(assets[0].asset_type, "API")

    def test_reads_marked_html_asset(self):
        assets = self.adapter._html_assets('<div data-asset-identifier="*.example.test" data-asset-type="Wildcard"></div>')
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].identifier, "*.example.test")

    def test_comparison_key_is_case_insensitive(self):
        items = [
            TargetAsset("Example", "API.Example.test", "API"),
            TargetAsset("example", "api.example.test", "api"),
        ]
        self.assertEqual(len(deduplicate_assets(items)), 1)


if __name__ == "__main__":
    unittest.main()
