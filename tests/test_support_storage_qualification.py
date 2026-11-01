"""Admission tests, not a substitute for the hosted PostgreSQL checks."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('support_storage', ROOT / 'tooling/support_storage_qualification.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SupportStorageAdmissionTest(unittest.TestCase):
    def test_nonhosted_execution_never_touches_docker(self):
        for environment in ({}, {'GITHUB_ACTIONS': 'true'},
                            {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'self-hosted', 'RUNNER_OS': 'Linux'}):
            with self.subTest(environment=environment), patch.dict(MODULE.os.environ, environment, clear=True), \
                    patch.object(MODULE.subprocess, 'run') as command:
                with self.assertRaises(RuntimeError):
                    MODULE.qualify('firefly-native-image-1-1-db', 'io.firefly.identity.native-image-smoke', '1-1')
                command.assert_not_called()

    def test_other_containers_and_wrong_ownership_labels_refuse(self):
        environment = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux'}
        with patch.dict(MODULE.os.environ, environment, clear=True), patch.object(MODULE.subprocess, 'run') as command:
            with self.assertRaises(RuntimeError):
                MODULE.qualify('existing-database', 'io.firefly.identity.native-image-smoke', '1-1')
            command.assert_not_called()
            command.return_value.returncode = 0
            command.return_value.stdout = '[{"Config":{"Labels":{"io.firefly.identity.native-image-smoke":"2-1"}}}]'
            with self.assertRaises(RuntimeError):
                MODULE.qualify('firefly-native-image-1-1-db', 'io.firefly.identity.native-image-smoke', '1-1')
            self.assertEqual(1, command.call_count)
