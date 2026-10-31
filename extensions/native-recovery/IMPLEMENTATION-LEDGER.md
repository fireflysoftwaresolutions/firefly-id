# Native owner implementation ledger

Approved spec: ../../docs/superpowers/specs/2026-10-31-native-recovery-design.md
Approved plan: ../../docs/superpowers/plans/2026-10-31-native-recovery.md

Ruling: Parent explicitly authorizes source edits on the shared main checkout under this module only. No commits/pushes.
Ruling: Unit tests are written before corresponding production behavior, but local red/green execution is prohibited by the resource floor. Every Java/build/provider result remains pending hosted CI; source checks do not substitute for it.
Integration: NativeCeremonyGateway is a mandatory qualified product-supplied ServiceLoader factory. Missing actual transport fails closed; no sample success gateway.

Source refinements after root snapshot 742e512: explicit credential-row locks and refresh, per-session user refresh marker, scoped admin veto, exact Domain record operation binding, local RFC3339 RPC mapper, unified firefly-recovery path, generic ffid* message keys and PIN status route.
Ruling: Password recovery verification uses the native stored hash provider directly to avoid ordinary deferred rehash transactions. Normal authentication remains unchanged.
Ruling: The native BPO verifier remains unreachable through HTTP and refuses absent/unqualified support-owner authorization; the real case/delegation owner contract is pending.
Validation: XML parsing and source inventory only; all Java/native/runtime test execution remains hosted-only.

Reservation replay refinement: exact Core reservation lookup now occurs before native budget debit. Completed positive/negative evidence returns the same opaque reference with verify=false; an in-flight/crash-pending reservation refuses another secret check. SQL reservation uniqueness remains the backstop. Native RPC known-negative completion returns canonical accepted=false; unknown/mismatched references refuse. Four regression methods added; no JVM execution performed locally.
