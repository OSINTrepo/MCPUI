"""Локальный профиль согласует модель UI, оркестратора, шлюза и загрузку весов."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parent.parent


class ComposeLoader(yaml.SafeLoader):
    pass


ComposeLoader.add_constructor('!reset', lambda loader, node: loader.construct_sequence(node))


def read(name):
    return yaml.load((ROOT / name).read_text(), Loader=ComposeLoader)


class LocalConfigTests(unittest.TestCase):
    def test_all_roles_use_downloaded_local_model(self):
        local = read('docker-compose.local.yml')['services']
        ui = read('config/librechat.yaml')
        spec = next(s for s in ui['modelSpecs']['list'] if s['name'] == 'local-osint-auto')
        alias = spec['preset']['model']
        self.assertEqual(spec['mcpServers'], ['orchestrator'])
        endpoint = next(e for e in ui['endpoints']['custom'] if e['name'] == spec['preset']['endpoint'])
        self.assertEqual(endpoint['titleModel'], alias)
        self.assertIn(alias, endpoint['models']['default'])
        env = local['orchestrator']['environment']
        self.assertEqual(env['ORCHESTRATOR_MODEL'], alias)
        self.assertEqual(env['ORCHESTRATOR_REPORT_MODEL'], alias)
        model = next(m for m in read('litellm/config.yaml')['model_list'] if m['model_name'] == alias)
        tag = model['litellm_params']['model'].removeprefix('ollama_chat/')
        self.assertIn('ollama pull ' + tag, local['ollama-init']['command'][0])
        self.assertTrue(model['model_info']['supports_function_calling'])
        self.assertLess(spec['preset']['maxContextTokens'], int(local['ollama']['environment']['OLLAMA_CONTEXT_LENGTH']))

    def test_gpu_is_optional_and_single_request_is_default(self):
        local = read('docker-compose.local.yml')['services']
        self.assertNotIn('deploy', local['ollama'])
        self.assertEqual(local['ollama']['environment']['OLLAMA_NUM_PARALLEL'], '1')
        devices = read('docker-compose.gpu.yml')['services']['ollama']['deploy']['resources']['reservations']['devices']
        self.assertEqual(devices, [{'driver': 'nvidia', 'count': 1, 'capabilities': ['gpu']}])

    def test_local_only_endpoint_and_initializer_failure_propagation(self):
        local = read('docker-compose.local.yml')['services']
        self.assertEqual(local['litellm']['environment']['OLLAMA_BASE_URL'], 'http://ollama:11434')
        self.assertEqual(local['litellm']['depends_on'], [])
        self.assertEqual(local['gigachat-proxy']['profiles'], ['cloud-gigachat'])
        self.assertEqual(local['ollama-init']['entrypoint'], ['/bin/sh', '-ec'])
        self.assertNotIn('ports', read('docker-compose.yml')['services']['ollama'])


if __name__ == '__main__':
    unittest.main()
