"""Контракт UI: рабочие URL чата, единый пресет и достаточный таймаут досье."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parent.parent


class UIConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = yaml.safe_load((ROOT / 'config/librechat.yaml').read_text())
        cls.registry = yaml.safe_load((ROOT / 'registry/servers.yaml').read_text())

    def test_endpoint_names_are_single_url_segments(self):
        endpoints = {e['name'] for e in self.config['endpoints']['custom']}
        for name in endpoints:
            self.assertFalse(any(c in name for c in '/?#%'), name)
        for spec in self.config['modelSpecs']['list']:
            self.assertIn(spec['preset']['endpoint'], endpoints)

    def test_default_has_report_tool_and_tested_model(self):
        defaults = [s for s in self.config['modelSpecs']['list'] if s.get('default')]
        self.assertEqual(len(defaults), 1)
        spec = defaults[0]
        self.assertEqual(spec['name'], 'deepseek-osint-auto')
        self.assertEqual(spec['mcpServers'], ['orchestrator'])
        self.assertEqual(spec['preset']['model'], 'deepseek-flash')
        endpoint = next(e for e in self.config['endpoints']['custom']
                        if e['name'] == spec['preset']['endpoint'])
        self.assertIn(spec['preset']['model'], endpoint['models']['default'])
        self.assertEqual(endpoint['titleModel'], 'deepseek-flash')

    def test_full_report_timeout_and_model_defaults(self):
        self.assertGreaterEqual(self.config['mcpServers']['orchestrator']['timeout'], 900000)
        env = next(s for s in self.registry['servers'] if s['id'] == 'orchestrator')['env']
        for key in ('ORCHESTRATOR_MODEL', 'ORCHESTRATOR_REPORT_MODEL'):
            self.assertEqual(env[key], '${' + key + ':-deepseek-flash}')
        self.assertEqual(env['REPORTS_URL_BASE'], '${REPORTS_URL_BASE:-http://localhost:8899}')


if __name__ == '__main__':
    unittest.main()
