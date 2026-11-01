"""Startup diagnostics preserve owned-container scope and never expose raw logs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'a' * 40
CONTAINER = 'b' * 64
PROJECT = 'firefly-id-sandbox-1234567890'


class StartupDiagnosticsTest(unittest.TestCase):
    def setUp(self):
        filename = ROOT / 'tooling/startup_diagnostics.py'
        if not filename.is_file():
            self.fail('Bounded startup diagnostics are not implemented')
        spec = importlib.util.spec_from_file_location('startup_diagnostics', filename)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def owned_state(self, directory):
        state = Path(directory)
        compose = state / 'compose.json'
        compose.write_text(json.dumps({'name': PROJECT}))
        (state / 'ownership.json').write_text(json.dumps({
            'mode': 'sandbox', 'created_by': 'firefly-id/scripts/generate.py',
            'project': PROJECT, 'compose': str(compose),
            'compose_sha256': hashlib.sha256(compose.read_bytes()).hexdigest(),
        }))
        return state

    def metadata(self, **changes):
        value = {'project': PROJECT, 'service': 'keycloak', 'status': 'exited',
                 'exit_code': 1, 'oom_killed': False}
        value.update(changes)
        return json.dumps(value).encode()

    def test_database_and_import_failures_return_fixed_categories_without_log_content(self):
        result = self.module.classify(
            'ERROR Failed to import realm at /private/DO-NOT-PRINT\n'
            'Caused by: org.postgresql.util.PSQLException: password=DO-NOT-PRINT\n'
            'org.keycloak.models.ModelDuplicateException: user@example.invalid')
        self.assertEqual(['DATABASE_FAILURE', 'REALM_IMPORT_FAILURE'], result['causes'])
        self.assertEqual(['ModelDuplicateException', 'PSQLException'], result['exception_classes'])
        for secret in ('DO-NOT-PRINT', 'user@example.invalid', '/private', 'org.postgresql'):
            self.assertNotIn(secret, json.dumps(result))

    def test_exception_classes_are_exact_allowlisted_simple_names(self):
        result = self.module.classify(
            'evil.DO_NOT_PRINTException FooIllegalStateException '
            'java.lang.IllegalStateException: sensitive-token')
        self.assertEqual(['IllegalStateException'], result['exception_classes'])
        self.assertNotIn('sensitive-token', json.dumps(result))

    def test_unrecognized_log_remains_unknown_without_copying_content(self):
        result = self.module.classify('secret://user:DO-NOT-PRINT@host/private')
        self.assertEqual(['UNKNOWN_STARTUP_FAILURE'], result['causes'])
        self.assertEqual([], result['exception_classes'])
        self.assertNotIn('DO-NOT-PRINT', json.dumps(result))

    def test_trusted_source_frames_keep_only_allowlisted_filenames_and_line_numbers(self):
        result = self.module.classify('java.lang.NullPointerException: DO-NOT-PRINT private value\n'
            '\tat org.keycloak.services.resources.admin.AdminConsole.secretMethod(AdminConsole.java:353)\n'
            '\tat org.keycloak.theme.DefaultThemeManager.lambda$secret$0(DefaultThemeManager.java:72)\n')
        self.assertIn('trusted_source_frames', result)
        self.assertEqual(['AdminConsole.java:353', 'DefaultThemeManager.java:72'], result['trusted_source_frames'])
        self.assertEqual(['UNKNOWN_STARTUP_FAILURE'], result['causes'])
        for private in ('DO-NOT-PRINT', 'secretMethod', 'lambda$', 'org.keycloak'):
            self.assertNotIn(private, json.dumps(result))

    def test_untrusted_or_malformed_source_frames_are_never_published(self):
        frames = [
            'at evil.org.keycloak.services.AdminConsole.get(AdminConsole.java:1)',
            'at org.keycloakx.services.AdminConsole.get(AdminConsole.java:1)',
            'at org.other.AdminConsole.get(AdminConsole.java:1)',
            'at org.keycloak.services.Private.get(DO-NOT-PRINT.java:1)',
            'at org.keycloak.services.AdminConsole.get(/private/AdminConsole.java:1)',
            'at org.keycloak.services.AdminConsole.get(AdminConsole.java:0)',
            'at org.keycloak.services.AdminConsole.get(AdminConsole.java:1000000)',
            'at org.keycloak.services.AdminConsole.get(AdminConsole.java:1-DO-NOT-PRINT)',
            'at org.keycloak.services.AdminConsole.get(AdminConsole.java:123) DO-NOT-PRINT',
            'at org.keycloak.services.AdminConsole.get(Unknown Source)',
            'message containing at org.keycloak.services.AdminConsole.get(AdminConsole.java:1)',
        ]
        result = self.module.classify('\n'.join(frames))
        self.assertIn('trusted_source_frames', result)
        self.assertEqual([], result['trusted_source_frames'])
        self.assertNotIn('DO-NOT-PRINT', json.dumps(result))

    def test_trusted_source_frames_preserve_order_deduplicate_and_stop_after_eight(self):
        frames = ['\tat org.keycloak.services.AdminConsole.get(AdminConsole.java:1)'] * 2
        frames += [f'\tat org.keycloak.services.AdminConsole.get(AdminConsole.java:{number})' for number in range(2, 12)]
        result = self.module.classify('\n'.join(frames))
        self.assertIn('trusted_source_frames', result)
        self.assertEqual(['AdminConsole.java:1', 'AdminConsole.java:2', 'AdminConsole.java:3', 'AdminConsole.java:4',
                          'AdminConsole.java:5', 'AdminConsole.java:6', 'AdminConsole.java:7', 'AdminConsole.java:8'],
                         result['trusted_source_frames'])

    def test_cli_stage_messages_do_not_pretend_to_identify_the_underlying_cause(self):
        result = self.module.classify("ERROR: Failed to run 'start' command.\n"
            'ERROR: Failed to start server in (production) mode\n'
            "For more details run the same command passing the '--verbose' option.\n"
            'ERROR: DO-NOT-PRINT secret://private/value')
        self.assertEqual(['UNKNOWN_STARTUP_FAILURE'], result['causes'])
        self.assertIn('cli_markers', result)
        self.assertEqual(['CLI_ERROR_DETAILS_AVAILABLE', 'CLI_SERVER_START_FAILED', 'CLI_START_COMMAND_FAILED'], result['cli_markers'])
        self.assertNotIn('DO-NOT-PRINT', json.dumps(result))

    def test_freemarker_subclasses_identify_theme_failures_without_confusing_other_parsers(self):
        for qualified, simple in [
                ('freemarker.core.InvalidReferenceException', 'InvalidReferenceException'),
                ('freemarker.template.TemplateModelException', 'TemplateModelException'),
                ('freemarker.core.ParseException', 'ParseException')]:
            with self.subTest(exception=simple):
                result = self.module.classify(f'Caused by: {qualified}: DO-NOT-PRINT private template value')
                self.assertEqual(['THEME_FAILURE'], result['causes'])
                self.assertEqual([simple], result['exception_classes'])
                self.assertNotIn('DO-NOT-PRINT', json.dumps(result))
        result = self.module.classify('other.parser.ParseException: DO-NOT-PRINT')
        self.assertEqual(['UNKNOWN_STARTUP_FAILURE'], result['causes'])
        self.assertEqual([], result['exception_classes'])

    def test_cli_configuration_messages_return_fixed_categories_without_parameters(self):
        for message, cause, marker in [
                ('ERROR: Failed to update server configuration.', 'AUGMENTATION_FAILURE', 'CLI_CONFIGURATION_UPDATE_FAILED'),
                ('Key material not provided to setup HTTPS.', 'HTTPS_KEY_MATERIAL_MISSING', 'CLI_HTTPS_KEY_MATERIAL_MISSING'),
                ('The following options are required: DO-NOT-PRINT', 'CONFIGURATION_FAILURE', 'CLI_REQUIRED_OPTIONS_MISSING'),
                ("Disabled option: '--DO-NOT-PRINT'", 'CONFIGURATION_FAILURE', 'CLI_DISABLED_OPTION')]:
            with self.subTest(marker=marker):
                result = self.module.classify(message + '\nprivate://DO-NOT-PRINT')
                self.assertEqual([cause], result['causes'])
                self.assertEqual([marker], result['cli_markers'])
                self.assertNotIn('DO-NOT-PRINT', json.dumps(result))

    def test_only_owned_keycloak_is_inspected_and_oom_state_is_preserved(self):
        commands = []
        def capture(command, **kwargs):
            commands.append(command)
            if 'ps' in command:
                return (CONTAINER + '\n').encode(), False
            if 'inspect' in command:
                return self.metadata(exit_code=137, oom_killed=True), False
            return b'java.lang.OutOfMemoryError: DO-NOT-PRINT', True
        with tempfile.TemporaryDirectory() as directory:
            state = self.owned_state(directory)
            with patch.object(self.module.sandbox, 'check_local_engine'), patch.object(self.module, 'capture', side_effect=capture):
                result = self.module.collect(state, SOURCE)
        self.assertEqual('COLLECTED', result['collection_status'])
        self.assertEqual({'status': 'exited', 'exit_code': 137, 'oom_killed': True}, result['process'])
        self.assertIn('OOM_KILLED', result['causes'])
        self.assertTrue(result['log_truncated'])
        self.assertEqual(SOURCE, result['source'])
        self.assertEqual(['keycloak'], commands[0][-1:])
        self.assertIn(PROJECT, commands[0])
        self.assertIn(str(state / 'compose.json'), commands[0])
        self.assertEqual(CONTAINER, commands[1][-1])
        self.assertEqual(CONTAINER, commands[2][-1])
        for secret in (CONTAINER, PROJECT, directory, 'DO-NOT-PRINT'):
            self.assertNotIn(secret, json.dumps(result))

    def test_foreign_container_labels_refuse_before_logs_are_read(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.owned_state(directory)
            with patch.object(self.module.sandbox, 'check_local_engine'), patch.object(self.module, 'capture', side_effect=[
                    ((CONTAINER + '\n').encode(), False), (self.metadata(project='another-project'), False)]) as capture:
                result = self.module.collect(state, SOURCE)
        self.assertEqual('REFUSED', result['collection_status'])
        self.assertEqual(['CONTAINER_OWNERSHIP_REFUSED'], result['causes'])
        self.assertEqual(2, capture.call_count)

    def test_missing_ambiguous_and_malformed_container_ids_refuse(self):
        for value in ('', CONTAINER + '\n' + 'c' * 64, 'DO-NOT-PRINT'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                state = self.owned_state(directory)
                with patch.object(self.module.sandbox, 'check_local_engine'), patch.object(self.module, 'capture', return_value=(value.encode(), False)) as capture:
                    result = self.module.collect(state, SOURCE)
                self.assertEqual(['CONTAINER_RESOLUTION_FAILED'], result['causes'])
                self.assertEqual(1, capture.call_count)

    def test_changed_owned_compose_refuses_before_any_docker_call(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.owned_state(directory)
            (state / 'compose.json').write_text('{}')
            with patch.object(self.module.sandbox, 'check_local_engine') as local, patch.object(self.module, 'capture') as capture:
                result = self.module.collect(state, SOURCE)
        self.assertEqual(['OWNERSHIP_REFUSED'], result['causes'])
        local.assert_not_called()
        capture.assert_not_called()

    def test_remote_engine_refuses_without_container_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.owned_state(directory)
            with patch.object(self.module.sandbox, 'check_local_engine', side_effect=RuntimeError('DO-NOT-PRINT')), patch.object(self.module, 'capture') as capture:
                result = self.module.collect(state, SOURCE)
        self.assertEqual(['LOCAL_ENGINE_REFUSED'], result['causes'])
        self.assertNotIn('DO-NOT-PRINT', json.dumps(result))
        capture.assert_not_called()

    def test_log_collection_failure_keeps_safe_process_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.owned_state(directory)
            with patch.object(self.module.sandbox, 'check_local_engine'), patch.object(self.module, 'capture', side_effect=[
                    ((CONTAINER + '\n').encode(), False), (self.metadata(), False), RuntimeError('DO-NOT-PRINT')]):
                result = self.module.collect(state, 'DO-NOT-PRINT')
        self.assertEqual('UNAVAILABLE', result['collection_status'])
        self.assertEqual(['LOG_COLLECTION_FAILED'], result['causes'])
        self.assertEqual(1, result['process']['exit_code'])
        self.assertIsNone(result['source'])
        self.assertNotIn('DO-NOT-PRINT', json.dumps(result))

    def test_capture_bounds_actual_child_output_in_memory(self):
        content, truncated = self.module.capture(
            [sys.executable, '-c', 'import sys; sys.stdout.write("x" * 1000000)'], limit=1024, timeout=2)
        self.assertLessEqual(len(content), 1024)
        self.assertTrue(truncated)

    def test_capture_deadline_stops_an_unresponsive_child(self):
        with self.assertRaises(TimeoutError):
            self.module.capture([sys.executable, '-c', 'import time; time.sleep(2)'], limit=1024, timeout=0.05)

    def test_bad_cli_arguments_never_echo_sensitive_input(self):
        result = subprocess.run([sys.executable, str(ROOT / 'tooling/startup_diagnostics.py'), '--DO-NOT-PRINT'],
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode)
        self.assertEqual(['INPUT_INVALID'], json.loads(result.stdout)['causes'])
        for secret in ('DO-NOT-PRINT', 'Traceback', str(ROOT)):
            self.assertNotIn(secret, result.stdout + result.stderr)
