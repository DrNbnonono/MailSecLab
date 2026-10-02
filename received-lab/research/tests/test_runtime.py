import json
import tempfile
import unittest
from pathlib import Path

try:
    from research import infrastructure, verification, stages
except ImportError:
    infrastructure = verification = stages = None


class RuntimeTests(unittest.TestCase):
    def test_compose_has_only_internal_network_and_loopback_ports(self):
        self.assertIsNotNone(infrastructure, 'isolated compose builder missing')
        config = infrastructure.configuration()
        self.assertTrue(config['networks']['lab']['internal'])
        self.assertTrue(all('container_name' not in service for service in config['services'].values()))
        for service in config['services'].values():
            for port in service.get('ports', []):
                self.assertTrue(port.startswith('127.0.0.1:'))

    def test_all_services_stay_under_resource_budget(self):
        self.assertIsNotNone(infrastructure, 'resource-bounded compose builder missing')
        services = infrastructure.configuration()['services'].values()
        self.assertLessEqual(sum(float(s['cpus']) for s in services), 4)
        self.assertLessEqual(sum(int(s['mem_limit'].removesuffix('m')) for s in services), 5120)

    def test_rspamd_no_result_is_not_pass(self):
        self.assertIsNotNone(verification, 'verifier result mapper missing')
        self.assertEqual(verification.rspamd_result({'symbols': {}})['status'], 'none')
        self.assertEqual(verification.rspamd_result({'symbols': {'R_DKIM_ALLOW': {'options': ['lab.test:s=research']}}})['status'], 'pass')
        self.assertEqual(verification.rspamd_result({'symbols': {'R_DKIM_REJECT': {}}})['status'], 'fail')

    def test_failing_predecessor_blocks_causal(self):
        self.assertIsNotNone(stages, 'stage evidence gate missing')
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td)
            (parent / 'completion.json').write_text(json.dumps({'stage': 'bootstrap', 'status': 'failed'}))
            with self.assertRaises(RuntimeError):
                stages.require_parent(parent, 'bootstrap')

    def test_unknown_process_result_cannot_be_negative_evidence(self):
        self.assertIsNotNone(verification, 'verifier adapter mapper missing')
        self.assertEqual(verification.parse_adapter('not JSON', 0)['status'], 'tool-error')
        self.assertEqual(verification.parse_adapter('{"status":"pass"}', 3)['status'], 'tool-error')


if __name__ == '__main__':
    unittest.main()
