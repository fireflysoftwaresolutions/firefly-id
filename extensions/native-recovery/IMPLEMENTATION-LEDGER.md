# Native owner implementation ledger

Approved spec: ../../docs/superpowers/specs/2026-10-31-native-recovery-design.md
Approved plan: ../../docs/superpowers/plans/2026-10-31-native-recovery.md

Ruling: Parent explicitly authorizes source edits on the shared main checkout under this module only. No commits/pushes.
Ruling: Unit tests are written before corresponding production behavior, but local red/green execution is prohibited by the resource floor. Every Java/build/provider result remains pending hosted CI; source checks do not substitute for it.
Integration: NativeCeremonyGateway is a mandatory qualified product-supplied ServiceLoader factory. Missing actual transport fails closed; no sample success gateway.
