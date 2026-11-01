"""The expiry transport must preserve genuine authority and bounded time."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_fixture', ROOT / 'tooling/native_integration_fixture.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class NativeExpiryFixtureTest(unittest.TestCase):
    def test_real_live_receipt_is_delayed_past_expiry_inside_transport_deadline(self):
        payload = json.dumps({'expiresAt': '2030-01-01T00:00:02Z'}).encode()
        self.assertAlmostEqual(2.1, fixture.receipt_expiry_delay(payload, 1893456000, 1893456120))

    def test_already_expired_or_long_receipt_cannot_claim_a_live_positive_control(self):
        for expiry in ('2030-01-01T00:00:00Z', '2030-01-01T00:01:00Z'):
            with self.subTest(expiry=expiry), self.assertRaises(RuntimeError):
                fixture.receipt_expiry_delay(json.dumps({'expiresAt': expiry}).encode(), 1893456000, 1893456120)

    def test_actor_must_outlive_receipt_to_isolate_the_receipt_refusal(self):
        with self.assertRaises(RuntimeError):
            fixture.receipt_expiry_delay(b'{"expiresAt":"2030-01-01T00:00:02Z"}', 1893456000, 1893456002)

    def test_invalid_receipt_does_not_echo_payload_in_diagnostics(self):
        for payload in (b'{"expiresAt":"secret-fixture-marker"}', b'secret-fixture-marker', b'{}', b'[]'):
            with self.subTest(payload=payload), self.assertRaisesRegex(RuntimeError, '^Invalid owned expiry receipt$'):
                fixture.receipt_expiry_delay(payload, 1893456000, 1893456120)
