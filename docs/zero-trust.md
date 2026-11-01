# Identity and authorization at every service boundary

Firefly Identity authenticates people and workloads. Each receiving Experience, Domain and Core service remains responsible for authenticating its actual caller and authorizing its current action. A successful ingress check, private network or signed token does not make all subsequent operations authorized.

## Receiver responsibilities

| Boundary | Required decision |
| --- | --- |
| Browser to Experience | Exact issuer/audience/signature/time, authorized session and CSRF where applicable, current actor/purpose and resource permission |
| Experience to Domain | Genuine workload authentication plus verified original human proof when required; exact tenant/action/resource and current policy |
| Domain to Core | Actual generated producer SDK contract, preserved proof, fresh Core authorization and authoritative resource/tenant binding |
| Native recovery callback | Distinct private workload credential plus signed restricted actor, exact phase and current native state |

Do not derive authority from an unsigned `X-Actor` header, caller-supplied subject/body, frontend claims or a machine token with invented human fields. A protected identity link connects an opaque subject to an owner; it does not grant access to every record belonging to that person. The opaque identity tenant namespace is separate from Configuration's resource tenant UUID. Resolve the actual current binding through its owning contract.

Unavailable, stale or indeterminate authorization refuses the protected operation. Audit refusal as well as mutation under the receiving owner's durable contract. Operation-specific constraints, step-up, maker/checker, amount, expiry and other applicable obligations must be enforced by the owner that can actually guarantee them.

## Jafly stays independent

Jafly provides provider-neutral Spring Security resource-server and authorization extension points. Its generic token/principal, current-state and policy mechanisms must not import Firefly Identity, Keycloak native classes or product realm names. Firefly-specific credential, native lock and PIN code stays in this distribution; business owner adapters stay with their owning service.

Published framework versions, source candidates and adoption by a running consumer are distinct facts. Published Jafly 26.10.23 does not establish a universal live authorization default in every microservice. Current-state and policy source work requires independent review, release and explicit consumer configuration/migration. See the [integration matrix](integration-contract.md) and [Jafly guide](jafly.md) for the actual qualified baseline.

Offline JWT validation can continue accepting an otherwise valid unexpired token after a user is blocked. Short lifetimes bound that exposure but do not provide immediate revocation. Receivers requiring immediate enforcement need a real current-state decision, with appropriate cache/revocation semantics and outage behavior. Native session retirement and user not-before are necessary controls; they do not remotely revoke every application's own session or change an offline decoder.

## Workforce acting for a customer

Customer and workforce identities have separate issuers, credentials, policies and owner links. Preserve the employee/BPO actor throughout the audit. Acting for a customer requires explicit, current, purpose- and resource-limited delegation from its genuine business owner. It must bind operator, customer, tenant, case, action, expiry and applicable approvals; revocation and employment/provider changes must take effect according to the approved enforcement policy.

Neither an administrator token exchange nor a supplied customer ID is sufficient evidence of that delegation. Do not replace the employee audit identity with a customer identity or hand an employee the customer's refresh token. Backoffice/terminal session design must enforce the actual delegation on each service hop and separate observation, support, privileged mutation and financial initiation.

The support case/call verification and delegation owner is a tracked platform gap. The CIAM PIN verification hook therefore stays closed. Self-only native account recovery cannot be reused to authorize a staff operator, a BPO action, customer impersonation or a payment. See [support PIN](support-pin.md) for the exact integration gate.
