# Third-party notices

SecWeaver's own source, templates, tests, documentation, and original baseline
rules are licensed under 0BSD.

The repository does not vendor scanner binaries, vulnerability databases, or
third-party rule packs. Running the default process uses separately distributed
software:

| Component | Project license at the reviewed version | Source |
| --- | --- | --- |
| Gitleaks | MIT | <https://github.com/gitleaks/gitleaks> |
| Trivy | Apache-2.0 | <https://github.com/aquasecurity/trivy> |
| Opengrep | LGPL-2.1 | <https://github.com/opengrep/opengrep> |
| OSV-Scanner | Apache-2.0 | <https://github.com/google/osv-scanner> |

The authoritative license is the one shipped by each upstream release.
Container base images, CI runners, actions, package databases, and any rules
added by an adopter may have additional terms. Review and retain those notices
when redistributing an internal runner image.

`config/tools.lock.toml` records the versions reviewed for v0.1.0; it is not a
substitute for an SBOM, legal review, checksums, signatures, or provenance.
