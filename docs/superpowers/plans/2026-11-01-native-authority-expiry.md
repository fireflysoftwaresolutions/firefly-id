# Native authority expiry qualification

Continue the approved independent production-security work without changing Jafly, selecting a KYC provider or enabling production recovery. Baseline: `9e785c9`.

1. Add an opt-in hosted fixture with separate synthetic actor-expiry and receipt-expiry identities in each customer/workforce realm. Preserve existing data, counters, source fixtures and ordinary qualification behavior.
2. Exercise genuine password admission and verify the same actor/proof before natural JWT expiry, then refuse its replay without state changes. Exercise genuine factors, consumption and online authorization verification; delay the exact accepted response until its receipt expires while the actor remains live. Prove no unlock/execution and no renewal/reset on retry.
3. Keep the short receipt lifetime and transport injection solely in the hosted test fixture. Capture no credential-bearing browser images, assertions or raw logs. Run local presubmit and actual hosted acceptance, retain failures and request an independent review.
4. Document expiry, consumption-versus-execution and institution escalation in the public native recovery guide. Publish only after strict documentation checks. State distinct coverage for ordinary lifecycle and expiry runs; do not infer supplier, legal or institutional acceptance.

The implementation requires no runtime-policy change if the existing guards pass. Changes to the public guide explain behavior, not engineering review history. Existing institution decisions remain explicit; no manual enablement or budget-reset workaround is introduced.

## Review and verification boundaries

The independent review found four qualification issues. Separate users now persist factors in distinct create-only, private files; the regression reproduced the former `EEXIST` failure before passing. Consumed Core authority is asserted as `PENDING`, not null. The relay records successful delivery only after flushing the exact accepted response, after its actual expiry and within the gateway deadline. Private snapshots now include the stored receipt expiry so repeated requests must preserve it.

Local presubmit after these corrections passed 124 Python and 36 Node tests. Two additional Java gateway tests exercise accepted HTTP responses carrying expired consumption/verification receipts; their execution belongs to hosted native qualification, not the local source check.

The expiry execution reports `authority-expiry-only` and cannot claim ordinary lifecycle/PIN coverage. The ordinary execution retains its own coverage declaration. Genuine source/image and public-documentation results are linked in the draft PR; no deployment, business-owner or regulatory approval is inferred from either lane. The final review introduced no production-policy or framework changes. Retained failed runs and original data remain preserved.
