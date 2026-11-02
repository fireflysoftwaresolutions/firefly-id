"""Public theme artifacts must be readable by the nonroot identity container."""
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('theme_permissions_builder', ROOT / 'tooling/build_theme.py')
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class ThemeBuildPermissionsTest(unittest.TestCase):
    def test_restrictive_umask_keeps_identical_public_artifacts_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            output = parent / 'private-output'
            output.mkdir(mode=0o700)
            secret = output / 'unrelated-secret'
            secret.write_bytes(b'private sentinel')
            secret.chmod(0o600)
            previous = os.umask(0o022)
            try:
                normal = BUILDER.build(parent / 'normal-output').read_bytes()
                os.umask(0o077)
                restricted = BUILDER.build(output)
            finally:
                os.umask(previous)
            self.assertEqual(restricted.read_bytes(), normal)
            for path in (output / 'themes').rglob('*'):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755 if path.is_dir() else 0o644, path)
            self.assertEqual(stat.S_IMODE((output / 'themes').stat().st_mode), 0o755)
            for path in (restricted, output / 'SHA256SUMS'):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            for path in (parent, output):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600)
            self.assertEqual(secret.read_bytes(), b'private sentinel')
            canonical = (ROOT / 'assets/brand/fonts/manrope-latin-wght-normal.woff2').read_bytes()
            with zipfile.ZipFile(restricted) as archive:
                for kind in ('login', 'account', 'admin', 'welcome'):
                    relative = f'firefly-id/{kind}/resources/fonts/manrope.woff2'
                    self.assertEqual(archive.read('theme/' + relative), canonical)
                    self.assertEqual((output / 'themes' / relative).read_bytes(), canonical)

    def test_symlink_targets_are_refused_before_public_or_private_files_change(self):
        targets = ('themes', 'themes/firefly-id', 'themes/firefly-id/admin/theme.properties',
                   'firefly-id-theme.jar', 'SHA256SUMS')
        for relative in targets:
            with self.subTest(target=relative), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                output = parent / 'output'
                output.mkdir(mode=0o700)
                private = parent / 'private'
                private.mkdir(mode=0o700)
                secret = private / 'secret'
                secret.write_bytes(b'private sentinel')
                secret.chmod(0o600)
                target = output / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                is_directory = relative in ('themes', 'themes/firefly-id')
                target.symlink_to(private if is_directory else secret, target_is_directory=is_directory)
                old_jar = output / 'firefly-id-theme.jar'
                if not old_jar.is_symlink():
                    old_jar.write_bytes(b'previous owned artifact')
                with self.assertRaises(ValueError):
                    BUILDER.build(output)
                self.assertEqual(secret.read_bytes(), b'private sentinel')
                self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
                if not old_jar.is_symlink():
                    self.assertEqual(old_jar.read_bytes(), b'previous owned artifact')

    def test_symlink_output_root_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            private = parent / 'private'
            private.mkdir(mode=0o700)
            output = parent / 'output'
            output.symlink_to(private, target_is_directory=True)
            with self.assertRaises(ValueError):
                BUILDER.build(output)
            self.assertEqual(list(private.iterdir()), [])
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
