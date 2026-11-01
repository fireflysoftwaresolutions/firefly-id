import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEMANTIC_TYPES = {
    "NativeAttestation", "NativeAudit", "NativeCeremony", "NativeContracts",
    "NativeIssuedChallenge", "NativeRefusal", "NativeState", "NativeSupportProof",
    "NativeTotpReplay", "NativeExecution", "NativeResource", "NativePinResource",
}


def java_code(source):
    return re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda match: "\n" * match.group().count("\n") + " ", source, flags=re.S)


class JavaImplementationNamingTest(unittest.TestCase):
    def sources(self):
        return ROOT.glob("extensions/*/src/main/java/**/*.java")

    def test_behavior_classes_including_nested_implementations_have_impl_suffix(self):
        failures = []
        for path in self.sources():
            code = java_code(path.read_text())
            for name in re.findall(r"\bclass\s+(\w+)", code):
                semantic_role = (path.parent.as_posix().endswith("/io/firefly/id/nativeauth")
                                 and path.stem == name and name in SEMANTIC_TYPES)
                if not name.endswith("Impl") and not semantic_role:
                    failures.append(f"{path.relative_to(ROOT)}: {name}")
        self.assertEqual(failures, [])
