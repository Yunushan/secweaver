# Security policy

## Supported versions

SecWeaver is currently alpha software. Security fixes are made on the current
`main` branch and the latest release. Older snapshots may not receive patches.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability, credential exposure,
private repository content, or an unredacted report.

When the project is published, enable the hosting provider's private
vulnerability-reporting feature and use it for initial contact. A maintainer
should acknowledge a complete report within seven days and provide a status
update within fourteen days. Before publication, downstream adopters should
replace this paragraph with their monitored private reporting channel.

Include:

- affected SecWeaver version or commit;
- a minimal reproduction without real credentials or private code;
- security impact and required attacker access;
- whether scanner output, logs, templates, or deployment gates are involved;
- any proposed mitigation.

## Response principles

Maintainers will avoid requesting production secrets, coordinate a patch and
advisory when the report is valid, credit the reporter if desired, and document
whether report schemas or user action are affected.

## Pipeline threat model

Pull-request jobs are untrusted. They should receive no deployment credentials,
write token, OIDC token, privileged container, host filesystem mount, or
container socket. Protected-branch jobs may publish reports or verify a
deployment only after policy files and workflow changes are reviewed.
