"""Hosted-only storage checks on the native image smoke test's empty owned database."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
import re
import subprocess
from threading import Barrier
import time


def require_owned_host(container, label, run):
    required = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux'}
    if (any(os.environ.get(key) != value for key, value in required.items())
            or not re.fullmatch(r'[0-9]+-[0-9]+', run)
            or container != 'firefly-native-image-' + run + '-db'
            or label != 'io.firefly.identity.native-image-smoke'):
        raise RuntimeError('Owned hosted smoke database required')
    result = subprocess.run(['docker', 'container', 'inspect', container], capture_output=True, timeout=10)
    if result.returncode:
        raise RuntimeError('Owned smoke database unavailable')
    metadata = json.loads(result.stdout)[0]
    if metadata.get('Config', {}).get('Labels', {}).get(label) != run:
        raise RuntimeError('Smoke database ownership mismatch')


def qualify(container, label, run):
    require_owned_host(container, label, run)

    def sql(statement):
        result = subprocess.run(['docker', 'exec', '-i', container, 'psql', '-X', '-q', '-A', '-t',
                                 '-v', 'ON_ERROR_STOP=1', '-U', 'native_smoke', '-d', 'native_smoke'],
                                input=statement, text=True, capture_output=True, timeout=20)
        if result.returncode:
            raise RuntimeError('Support storage invariant failed')
        return result.stdout.strip()

    if sql('SELECT count(*) FROM ff_native_support_proof;') != '0':
        raise RuntimeError('Support storage fixture must start empty')
    # Legacy rows remain representable after the additive migration; service tests refuse their consumption.
    sql("INSERT INTO ff_native_support_proof (id,grant_digest,realm_id,subject,pin_generation,expires_at,verified) "
        "VALUES ('storage-legacy','legacy-grant','fixture-realm','legacy-user','generation',1,true);")
    if sql("SELECT count(*) FROM ff_native_support_proof WHERE id='storage-legacy' AND nonce_digest IS NULL "
           "AND status IS NULL AND consumed_at IS NULL;") != '1':
        raise RuntimeError('Legacy support row binding changed')

    barrier = Barrier(2)

    def contender(index):
        barrier.wait(timeout=10)
        # Different customer/grant rows compete for the same globally unique nonce digest.
        return sql(f"SET application_name='firefly-support-contender-{index}'; "
                   "BEGIN; SET LOCAL statement_timeout='10s'; "
                   "INSERT INTO ff_native_support_proof "
                   "(id,grant_digest,nonce_digest,realm_id,subject,pin_generation,expires_at,verified,status) "
                   f"VALUES ('storage-race-{index}','race-grant-{index}','shared-nonce','fixture-realm',"
                   f"'customer-{index}','generation',1,true,'VERIFIED') "
                   "ON CONFLICT (nonce_digest) DO NOTHING RETURNING id; SELECT pg_sleep(5); COMMIT;")

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(contender, index) for index in (1, 2)]
        observed_contention = False
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not all(future.done() for future in futures):
            waiting = sql("SELECT count(*) FROM pg_stat_activity WHERE application_name IN "
                          "('firefly-support-contender-1','firefly-support-contender-2') "
                          "AND wait_event_type='Lock' AND wait_event='transactionid';")
            if waiting == '1':
                observed_contention = True
                break
            time.sleep(0.1)
        results = [future.result() for future in futures]
    if not observed_contention:
        raise RuntimeError('Actual support nonce transaction contention was not observed')
    if (sum(bool(value) for value in results) != 1
            or sql("SELECT count(*) FROM ff_native_support_proof WHERE nonce_digest='shared-nonce';") != '1'):
        raise RuntimeError('Concurrent support nonce fence failed')

    sql("INSERT INTO ff_native_audit (id,realm_id,subject,event_type,reference_id,occurred_at,actor_issuer,"
        "actor_subject,support_case_id,support_call_id,support_nonce_digest) VALUES "
        "('storage-audit','fixture-realm','customer','SUPPORT_PIN_ACCEPTED','storage-reference',1,"
        "'https://staff.example/realms/staff','operator','case','call','shared-nonce');")
    # A failed audit write must roll back the proof transition in the same transaction.
    sql("DO $$ BEGIN BEGIN UPDATE ff_native_support_proof SET status='CONSUMED',consumed_at=2 "
        "WHERE nonce_digest='shared-nonce'; INSERT INTO ff_native_audit (id) VALUES ('storage-audit'); "
        "RAISE EXCEPTION 'Expected duplicate audit refusal'; EXCEPTION WHEN unique_violation THEN NULL; END; "
        "IF NOT EXISTS (SELECT 1 FROM ff_native_support_proof WHERE nonce_digest='shared-nonce' "
        "AND status='VERIFIED' AND consumed_at IS NULL) THEN RAISE EXCEPTION 'Rollback failed'; END IF; END $$;")
    # Check the append-only trigger also protects newly added operator/case attribution.
    sql("DO $$ BEGIN BEGIN UPDATE ff_native_audit SET actor_subject='replacement' WHERE id='storage-audit'; "
        "RAISE EXCEPTION 'Expected audit update refusal'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; "
        "BEGIN DELETE FROM ff_native_audit WHERE id='storage-audit'; RAISE EXCEPTION 'Expected audit delete refusal'; "
        "EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$;")
    if sql("SELECT actor_subject||':'||support_case_id||':'||support_call_id "
           "FROM ff_native_audit WHERE id='storage-audit';") != 'operator:case:call':
        raise RuntimeError('Support audit attribution changed')
    return {'scope': 'Owned empty PostgreSQL storage only; not native service or BPO acceptance',
            'legacy_nullable_binding': True, 'concurrent_cross_customer_nonce_fence': True,
            'proof_audit_rollback': True, 'attribution_append_only': True}
