# Reports

SecWeaver preserves scanner-specific evidence and emits a portable normalized
report set. Reports are intended for CI artifacts, code-scanning ingestion,
test-report ingestion, and human review.

Reports can still contain private metadata after redaction. Store them with
appropriate access controls and retention.

## Output layout

The default report directory is `secweaver-reports/`:

```text
secweaver-reports/
├── .secweaver-output
├── raw/
│   ├── gitleaks.json
│   ├── trivy.json
│   ├── opengrep.sarif
│   └── osv.json
├── logs/
│   ├── gitleaks.log
│   ├── trivy.log
│   ├── opengrep.log
│   ├── osv.log
│   └── sbom.log
├── sbom.cdx.json
├── summary.json
├── verdict.json
├── summary.md
├── junit.xml
├── results.sarif
└── report-manifest.json
```

Files are present only when the corresponding scanner or SBOM task ran far
enough to create them. If `reports.retain_raw = false`, files under `raw/` are
removed after parsing. Logs are deleted by default.

SecWeaver creates the marker for artifact identification, but never treats it
as authority to delete prior content. The report directory must be absent or
empty. Remove an earlier output directory explicitly in trusted CI cleanup, or
select a unique directory for each run.

## Current format behavior

The current implementation emits the normalized JSON, Markdown, JUnit XML, and
SARIF files on every completed orchestration run. It also generates CycloneDX
when `scan.generate_sbom = true`.

The `reports.formats` configuration key declares the intended standard formats,
but the current writer does not yet use it to selectively disable individual
normalized outputs. Do not document per-format selection until that behavior is
implemented and tested.

`reports.privacy = "strict"` is an enforced retention preset: it forces
`retain_raw = false`, `retain_logs = false`, and
`include_absolute_paths = false` after configuration overlays are applied.
Standard privacy still rejects absolute-path output, but lets a trusted caller
opt into sanitized raw reports or redacted log tails.

## `summary.json`

`summary.json` is the primary normalized record. It contains:

- SecWeaver schema and package version;
- project name;
- start, finish, and duration;
- selected profile, target kind, execution mode, and offline flag;
- runner OS, release, architecture, and Python version;
- detected source-language file counts;
- scanner status, duration, exit code, execution mode, reported version, and
  finding count;
- normalized findings;
- policy result, reasons, and severity counts.

This is a SecWeaver schema, not a replacement for raw scanner schemas.
Downstream systems should check `schema_version`.

## `verdict.json`

`verdict.json` is a compact policy result containing:

- `passed`;
- policy-oriented `exit_code` of 0 or 1;
- blocking reasons;
- finding counts.

The process can return a different code for configuration or scanner
infrastructure failures. Consumers that need operational status should preserve
the actual process exit code and inspect scanner states in `summary.json`.

## `summary.md`

The Markdown summary contains the policy verdict, scanner status, finding
counts, blocking reasons, and detected languages. It is designed for a CI job
summary or downloadable human-readable artifact.

It intentionally avoids source snippets. It is not a complete audit record.

## `junit.xml`

The JUnit report contains:

- one test case for each scanner or SBOM task;
- an error for missing, failed, timed-out, or invalid-report tasks;
- a skipped element for inapplicable tasks;
- a policy test case and failure text when policy blocks.

JUnit is an interchange mechanism. A CI test dashboard may present scanner
errors and security policy failures differently.

## `results.sarif`

The normalized SARIF document uses SARIF 2.1.0 and combines findings from all
implemented scanners under the `SecWeaver` driver.

Each normalized result includes:

- a namespaced rule ID in the form `scanner/rule`;
- normalized SARIF level;
- message;
- stable SecWeaver fingerprint when available;
- severity and category properties;
- a workspace-relative location when available.

The generated SARIF omits source snippets. Its severity mapping is:

| SecWeaver severity | SARIF level |
| --- | --- |
| Critical | error |
| High | error |
| Medium | warning |
| Low | note |
| Info | note |
| Unknown | warning |

SARIF ingestion capabilities and permissions differ among CI providers. A
valid SARIF artifact does not prove that a provider uploaded or displayed it.

SARIF 2.1.0 is an OASIS standard:
[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).

## `sbom.cdx.json`

Trivy generates the CycloneDX JSON SBOM for a source filesystem or OCI image.
The document's declared `specVersion` is controlled by the pinned Trivy
version. SecWeaver must not relabel it as a newer CycloneDX version.

Validate the emitted document against the schema version it declares before
using it as release evidence. The current CycloneDX specification may be newer
than the format supported by a pinned generator:
[CycloneDX specification](https://cyclonedx.org/specification/overview/).

A source SBOM and an artifact SBOM answer different questions. For releases,
retain both when practical and label their subjects clearly.

SBOMs can contain private package names, versions, file paths, repositories,
suppliers, and internal component relationships. The SBOM bypasses
SecWeaver's raw-report sanitization because altering its structured identity
data could invalidate it. Treat it as a sensitive artifact.

## Raw scanner reports

SecWeaver parses and then sanitizes the raw reports:

- Gitleaks secret, match, source line, author, email, and commit message fields
  are replaced;
- Trivy secret match, code, and line fields are replaced;
- Opengrep SARIF snippets are removed;
- recognized sensitive keys in structured data are redacted;
- the absolute target path is replaced with a relative representation.

Gitleaks is also invoked with full secret redaction.

Sanitization is defense in depth, not a publication approval. Unknown fields,
package names, filenames, references, and future scanner-schema changes can
still reveal private information.

## Logs

Scanner standard output and error are captured while each process runs. With
the default `reports.retain_logs = false`, SecWeaver deletes those captures
before report publication. If a trusted configuration explicitly enables log
retention, SecWeaver replaces each capture with a bounded, heuristically
redacted tail; it never retains the complete scanner stream.

Redaction is not proof that a retained tail is publication-safe. Restrict log
access and review schema or verbosity changes when upgrading a scanner.

## `report-manifest.json`

The manifest records each generated file's relative path, size, and SHA-256
digest, plus manifest generation time.

It supports accidental-corruption checks and evidence inventory. It is not a
digital signature, an in-toto attestation, or SLSA provenance. Anyone able to
replace both a report and the manifest can generate matching hashes.

Sign the manifest in a separate controlled step when authenticity is required.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Scan policy passed |
| 1 | Security policy failed |
| 2 | Configuration, path, or validation error |
| 3 | Required scanner or report infrastructure failure |
| 4 | `doctor` found a required native scanner command unavailable |

CI adapters should upload reports in an “always run” or equivalent post-step
and then return the original SecWeaver exit code.

## Retention guidance

- Keep normalized summaries long enough to support remediation and audit.
- Keep raw reports and logs for the shortest useful period.
- Restrict SBOMs and internal package metadata.
- Do not attach private reports to a public issue or pull request.
- Separate public-project reports from private-company reports.
- Record the scanner/database versions used for material release decisions.
