"""Offline fixture guards; native matcher execution belongs to hosted qualification."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class HostedPasswordPreflightTest(unittest.TestCase):
    def helper(self):
        self.assertTrue((ROOT / 'tooling/hosted_password_preflight.py').is_file(), 'Native password preflight is missing')
        return module('hosted_password_preflight', 'tooling/hosted_password_preflight.py')

    def test_generator_retries_only_rejected_fresh_candidates_and_bounds_exhaustion(self):
        generator = module('password_generator', 'scripts/generate.py')
        self.assertTrue(hasattr(generator, 'synthetic_password'), 'Bounded fixture password generation is missing')
        observed = []
        def accepted(value):
            observed.append(value)
            return value == 'Aa1accepted'
        with patch.object(generator.secrets, 'token_urlsafe', side_effect=['rejected', 'accepted']):
            self.assertEqual(generator.synthetic_password(accepted), 'Aa1accepted')
        self.assertEqual(observed, ['Aa1rejected', 'Aa1accepted'])
        with patch.object(generator.secrets, 'token_urlsafe', return_value='rejected') as random:
            with self.assertRaisesRegex(ValueError, 'retry bound'):
                generator.synthetic_password(lambda _: False)
            self.assertEqual(random.call_count, 8)
        with patch.object(generator.secrets, 'token_urlsafe', return_value='private'):
            with self.assertRaises(RuntimeError):
                generator.synthetic_password(lambda _: (_ for _ in ()).throw(RuntimeError('matcher unavailable')))

    def test_nonhosted_preflight_refuses_before_process_or_output(self):
        helper = self.helper()
        with patch.dict(os.environ, {}, clear=True), patch.object(helper.subprocess, 'run') as process:
            with self.assertRaises(ValueError): helper.prepare()
            process.assert_not_called()

    def test_password_prevalidation_failure_leaves_no_partial_fixture(self):
        generator = module('password_generator', 'scripts/generate.py')
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            theme = root / 'theme'
            for kind in ('login', 'account', 'admin', 'email', 'welcome'):
                (theme / kind).mkdir(parents=True)
                (theme / kind / 'theme.properties').write_text('parent=base\n')
            output = root / 'fixture'
            with patch.object(sys, 'argv', ['generate.py', '--mode', 'sandbox', '--output', str(output), '--theme-dir', str(theme)]), \
                 patch.object(generator, 'synthetic_password', side_effect=ValueError('matcher refused')):
                with self.assertRaises((ValueError, SystemExit)): generator.main()
            self.assertFalse(output.exists())

    def test_generator_opt_in_refuses_nonhosted_before_output(self):
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / 'fixture'
            result = subprocess.run(['python3', str(ROOT / 'scripts/generate.py'), '--mode', 'sandbox',
                                     '--output', str(output), '--hosted-password-preflight'],
                                    env={key: value for key, value in os.environ.items() if not key.startswith(('GITHUB_', 'RUNNER_'))},
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('requires GitHub-hosted Linux Actions', result.stderr)
            self.assertFalse(output.exists())

    def test_native_matcher_sends_values_only_on_stdin_and_rejects_unknown_output(self):
        helper = self.helper()
        with tempfile.TemporaryDirectory() as parent:
            directory = Path(parent)
            with patch.object(helper.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'ACCEPT\nREJECT\n', b'')) as process:
                self.assertEqual(helper.match(directory, ['PRIVATE-ONE', 'PRIVATE-TWO']), [True, False])
                args, kwargs = process.call_args
                self.assertNotIn('PRIVATE', str(args))
                self.assertEqual(kwargs['input'], b'PRIVATE-ONE\nPRIVATE-TWO\n')
            for returncode, stdout in [(1, b'ACCEPT\n'), (0, b'PRIVATE\n'), (0, b'ACCEPT\nACCEPT\n')]:
                with patch.object(helper.subprocess, 'run', return_value=subprocess.CompletedProcess([], returncode, stdout, b'PRIVATE')):
                    with self.assertRaises(ValueError) as error: helper.match(directory, ['PRIVATE'])
                    self.assertNotIn('PRIVATE', str(error.exception))

    def test_container_guard_refuses_running_foreign_or_wrong_image(self):
        helper = self.helper()
        owner = {'run': '123-1', 'container': 'ff-password-preflight-123-1', 'container_id': 'a' * 64,
                 'image': 'quay.io/keycloak/keycloak:26.8.1@sha256:' + 'b' * 64, 'image_id': 'sha256:' + 'c' * 64}
        actual = {'Id': owner['container_id'], 'Name': '/' + owner['container'], 'Image': owner['image_id'],
                  'Config': {'Image': owner['image'], 'Labels': {helper.LABEL: owner['run']}},
                  'State': {'Status': 'created', 'Running': False}, 'Mounts': [], 'HostConfig': {'NetworkMode': 'none'}}
        helper.validate_container(owner, actual)
        for key, value in [('Id', 'd' * 64), ('Image', 'sha256:foreign'), ('Mounts', [{'Source': '/foreign'}]),
                           ('State', {'Status': 'running', 'Running': True}),
                           ('Config', {'Image': owner['image'], 'Labels': {helper.LABEL: 'old-run'}})]:
            with self.subTest(key=key), self.assertRaises(ValueError): helper.validate_container(owner, {**actual, key: value})

    def test_checker_refuses_stale_receipt_changed_library_and_symlink(self):
        helper = self.helper()
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent).resolve()
            directory = root / '.state/password-preflight-123-1'
            (directory / 'libraries').mkdir(parents=True)
            (directory / 'classes').mkdir()
            library = directory / 'libraries/native.jar'; library.write_bytes(b'library')
            (directory / 'classes/SyntheticPasswordDenylist.class').write_bytes(b'class')
            denylist = root / 'denylist.txt'; denylist.write_bytes(b'baseline')
            source = root / 'helper.java'; source.write_bytes(b'source')
            owner = {'run': '123-1', 'root': str(directory), 'container': 'ff-password-preflight-123-1', 'image': 'pinned-image',
                     'files': {'libraries/native.jar': hashlib.sha256(b'library').hexdigest(),
                               'classes/SyntheticPasswordDenylist.class': hashlib.sha256(b'class').hexdigest()},
                     'denylist_sha256': hashlib.sha256(b'baseline').hexdigest(), 'source_sha256': hashlib.sha256(b'source').hexdigest()}
            receipt = directory / 'ownership.json'; receipt.write_text(json.dumps(owner))
            with patch.object(helper, 'ROOT', root), patch.object(helper, 'DENYLIST', denylist), patch.object(helper, 'JAVA_SOURCE', source), \
                 patch.object(helper, 'hosted', return_value='123-1'), patch.object(helper, 'pinned_image', return_value='pinned-image'), \
                 patch.object(helper, 'inspect_container'), patch.object(helper, 'match', return_value=[True]) as matcher:
                self.assertTrue(helper.load_checker()('private'))
                receipt.write_text(json.dumps({**owner, 'run': '122-1'}))
                with self.assertRaises(ValueError): helper.load_checker()
                receipt.write_text(json.dumps(owner)); library.write_bytes(b'changed')
                with self.assertRaises(ValueError): helper.load_checker()
                library.unlink(); library.symlink_to(source)
                with self.assertRaises(ValueError): helper.load_checker()
                self.assertEqual(matcher.call_count, 1)

