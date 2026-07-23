import unittest

from client_agent.agent import parse_assets, parse_metadata


class ClientAgentParserTests(unittest.TestCase):
    def test_reads_server_rendered_scope_table_without_network(self):
        assets = parse_assets(
            "<table><tr><th>Asset</th><th>Type</th></tr><tr><td>api.example.test</td><td>API</td></tr></table>"
        )
        self.assertEqual([(item.identifier, item.asset_type) for item in assets], [("api.example.test", "API")])

    def test_reads_whitelisted_program_metrics(self):
        metadata = parse_metadata(
            {"attributes": {"resolved_reports": 12, "minimum_bounty": "100", "currency": "USD"}}
        )
        self.assertEqual(metadata["resolved_reports"], 12)
        self.assertEqual(metadata["minimum_bounty"], "100")
        self.assertEqual(metadata["currency"], "USD")


if __name__ == "__main__":
    unittest.main()
