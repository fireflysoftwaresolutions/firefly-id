# Report a security vulnerability

Use [GitHub's private vulnerability reporting](https://github.com/fireflysoftwaresolutions/firefly-id/security/advisories/new) to report a suspected vulnerability in Firefly Identity's configuration, themes, native extensions or integration examples. Reports are visible to the repository's authorized security maintainers. Do not publish an exploit, affected customer details or credentials in a public issue or pull request.

Include the affected Firefly Identity revision or image digest, Keycloak version, component, expected behavior, observed behavior and a minimal reproduction using synthetic data. Explain the required access and likely impact. Remove tokens, passwords, PINs, OTP secrets, action links, private keys, production exports and personal information from attachments. Do not test against another organization's identity service without its permission.

The distribution currently pins Keycloak 26.8.1. Include the actual installed version even if it differs; compatibility and remediation depend on the installed server and provider artifacts. Source and test results do not constitute an institutional deployment approval or a support-service agreement.

For a vulnerability in unmodified Keycloak itself, follow the [upstream Keycloak security reporting process](https://www.keycloak.org/security). Mention any Firefly-specific impact in a private report here. Coordinate disclosure and remediation through the private report before publishing technical details.

An active operational incident also needs the institution's own incident-response channel. Repository reporting does not replace containment, customer communications or applicable regulatory reporting. The [incident-response guide](docs/observability-incidents.md) describes the operational responsibilities.
