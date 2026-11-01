# Retained data, migration and recovery

The identity database, encryption keys, service-owned journals and application records form a retained system. Starting a new sandbox, regenerating secrets or importing a new realm is not a migration of that system. This guide explains what must travel together and how to rehearse restoration without changing the original evidence or granting fresh access.

## Inventory each owner

| Owner | Retained state | Why it matters |
| --- | --- | --- |
| Keycloak | Users, credentials, authenticators, sessions, clients, keys/configuration and federation links | Establishes identity and factor/session lifecycle; mutable events are not external immutable custody |
| Native extension | Lock generations, ceremonies, durable reservations/replay protection, protected snapshots, execution/audit records, PIN generations and notification outbox | Prevents replay, conflicting transitions and counter reset; journals can be needed after browser/receipt expiry |
| Core SCA | Known-password unlock transactions and exact execution records | Reconciliation must identify the original operation, reservation and budget; PIN lifecycle itself is native-owned |
| Core KYCB | KYC/KYB records, credential-loss cases/provider-start/session bindings, subject/epoch budgets, grants and execution/audit state | Ambiguous provider starts and consumed grants cannot be replaced with a new attempt |
| Customer Domain | Provider orchestration configuration and integration contract; no recovery database | Calls the actual owners through the genuine SDK and native boundaries |
| Secret/evidence owners | Signing/decryption/PIN keys, mounted workload secrets, verifier evidence and provider/session references | Restoring database rows without needed keys or external evidence may leave them unverifiable or undecryptable |

The exact schema and installer roles are service-owned. Keycloak should not acquire Core business tables, and Domain should not create a second authoritative recovery database. Inventory dependencies and retention before scheduling any restore.

## Import is not update

The sandbox's `--import-realm` creates a missing realm and skips one that already exists. Editing a generated JSON file and restarting does not apply a reviewed policy update. The generator refuses an existing directory rather than rotate its secrets or repoint its Compose ownership.

Keep the original state path and ownership marker with the corresponding database. A new output creates a different project and identity population. Do not relabel it as the restored original, overwrite an ownership file, copy an unrelated credential file into retained state or reset a user's factor to make an old test script pass.

For actual retained realm/client changes, use the supported administration/migration interface under a reviewed change plan. Read back the effective settings, qualify affected users/clients and keep an exact pre-change checkpoint.

## Native installation changes schema

The optional provider contributes JPA mappings and versioned Liquibase changes at Keycloak startup. Installing the JAR can register additive database changes **even when recovery is disabled**. Its enable flags govern behavior, not installation migration.

Before first native installation or upgrade, record the current image/provider/theme/configuration versions; back up the owned database; restore to an isolated target; install the exact candidate there; and verify entity discovery, constraints, triggers, roles and ordinary identity operations. Include existing users, permanent holds and retained recovery records in the approved rehearsal dataset. Synthetic clean-database success is not retained-data acceptance.

The Core installers have independent objects and role requirements. Apply each owner through its own deployment process. Do not run a production installer from a copied test command or against a URL whose environment/ownership has not been established.

## Backup and restore rehearsal

An approved runbook should identify the exact source/target, responsible operator, maintenance boundary, backup encryption/access, consistent recovery point, required keys, application/provider dependencies, external-delivery isolation and acceptance/rollback criteria. A restore is potentially destructive; this handbook intentionally supplies no generic overwrite/drop command.

1. Record a consistent checkpoint and stop or coordinate writers as required by the approved database and application procedure. Include each owner's correlation/journal position; separately timed snapshots can recreate an impossible cross-service state.
2. Preserve the original backup and failed-state evidence. Restore into a **new isolated reviewed target**, using the matching compatible images/configuration and controlled access.
3. Mount the required historical decryption/PIN keys under their original versions and deadlines. Never invent replacement bytes under an old version name. Restore other secrets through the approved secret manager, not through logs or a ticket.
4. Prevent real customer mail, external verifier submissions and application traffic during rehearsal. An old outbox row remains a delivery intent; isolation must stop accidental replay to a live channel.
5. Verify discovery/issuer, credential checks, required factors, protected links, lock/hold retention, session/refresh behavior, exact original case/grant budgets, lease ownership and journal reconciliation. Check database privileges and append-only protections using the actual runtime roles.
6. Record results and reconcile each owner before accepting traffic. Inconsistency, missing evidence or an unknown execution remains unresolved; do not manufacture a new grant, clear counters or approve a new human assertion to make the state appear successful.

Define recovery-point and recovery-time objectives with operational owners and measure the rehearsal. Passing a health endpoint does not establish either objective.

## Keys and retention

Signing-key rotation, PIN pepper verification windows and recovery-record encryption are different lifecycles. The [operations guide](operations.md), [support PIN guide](support-pin.md) and [credential-loss key procedure](credential-loss-recovery.md) explain their supported mechanisms.

Keep previous encryption versions while retained ceremonies/outbox records need them. A single-key file replacement is not ciphertext migration. Retaining an old verification key beyond its approved deadline is also not a safe default. Document who approves retention, revocation, evidence access and eventual destruction; test missing/revoked-key failure without recreating plaintext.

Legal retention and deletion depend on record purpose and jurisdiction. Authentication events, banking audit evidence, provider documents and biometric templates do not share one default lifetime. Keycloak's seven-day synthetic event expiry is not the institution's retention schedule. Raw proofing documents and biometrics remain outside Keycloak attributes and application tokens with their designated owner.

## Upgrade and rollback

Review supported upgrade paths, release notes, inherited templates, SPI/API and schema changes. Build an immutable candidate and run the full applicable protocol, factor, locale, console, recovery, provider and receiving-service checks. Rehearse the exact retained database and selected multi-node topology.

If the new version changes schema, restarting the older binary against that migrated database is not a validated rollback. An approved rollback restores the pre-change state into a compatible reviewed target, with matching keys/configuration and a reconciled application/provider checkpoint. Preserve the failed upgrade's data and records. Read [operations](operations.md) for the change sequence.

## What is currently proved

The actual synthetic native lanes prove retained lock state across restart, scoped concurrent execution, old session retirement, exact response-loss journal reconciliation, and notification retry/terminal state across an owned Core restart. Those results do not qualify arbitrary backup restoration, cross-owner point-in-time recovery, a retained institution database, full multi-node crash/HA behavior or a production migration. [Qualification and acceptance](evidence.md) records the exact scope and remaining owners.
