"""Artifact admission checks; synthetic bytecode is not JVM qualification."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('package_native', ROOT / 'tooling/package_native.py')
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)
AUTHENTICATOR = 'META-INF/services/org.keycloak.authentication.AuthenticatorFactory'
SUPPORT_OWNER = 'META-INF/services/io.firefly.id.nativeauth.NativeSupportAuthorization$Factory'


class NativePackagingTest(unittest.TestCase):
    def archive(self, directory, extra=None, omit=()):
        path = Path(directory) / 'candidate.jar'
        resources = ROOT / 'extensions/native-recovery/src/main/resources'
        with zipfile.ZipFile(path, 'w') as jar:
            for name in PACKAGE.REQUIRED['native-recovery']:
                if name not in omit:
                    source = resources / name
                    jar.writestr(name, source.read_bytes() if source.exists() else b'index')
            for name in ('LICENSE', 'NOTICE'):
                jar.writestr('META-INF/' + name, (ROOT / name).read_bytes())
            jar.writestr('io/firefly/id/nativeauth/Fixture.class', struct.pack('>IHH', 0xCAFEBABE, 0, 65))
            for name, value in (extra or {}).items():
                jar.writestr(name, value)
        return path

    def test_distribution_requires_privileged_authenticator_registration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(directory, omit=(AUTHENTICATOR,))
            with self.assertRaises((ValueError, KeyError)):
                PACKAGE.inspect(path, 'native-recovery')

    def test_default_distribution_cannot_ship_a_support_authorization_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(directory, {SUPPORT_OWNER: 'example.PermissiveFixtureFactory'})
            with self.assertRaises(ValueError):
                PACKAGE.inspect(path, 'native-recovery')

    def test_current_distribution_is_admitted_without_support_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            result = PACKAGE.inspect(self.archive(directory), 'native-recovery')
            self.assertEqual(21, result['java_release'])
            self.assertEqual(1, result['class_count'])
