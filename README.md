# SecWeaver

SecWeaver is a public, vendor-neutral security CI/CD kit. One small Python
orchestrator runs the same policy across GitHub, GitLab, Gitea, Forgejo,
Bitbucket, Woodpecker, Drone, Jenkins, Azure Pipelines, CircleCI, Tekton, and
Argo-based delivery. It normalizes Gitleaks, Trivy, Opengrep, and OSV-Scanner
results into portable reports and a deterministic pass/fail verdict.

The SecWeaver code and its original baseline rules use the permissive
[0BSD license](LICENSE). External scanners, community rules, CI platforms, and
container images keep their own licenses.

> **Status:** v0.1.0 is an alpha reference implementation. It is designed to be
> reviewed and adapted. No security scanner or pipeline can guarantee that
> software is vulnerability-free.

## What you get

- A dependency-free Python 3.11+ policy engine with no shell evaluation.
- Typed adapters for Gitleaks, Trivy, Opengrep, OSV-Scanner, and CycloneDX SBOM
  generation.
- Thin, editable CI templates that all call the same `secweaver` command.
- Balanced, advisory, strict, and air-gapped policy overlays.
- Sanitized normalized JSON, Markdown, JUnit XML, and SARIF 2.1.0 reports,
  plus a CycloneDX SBOM and artifact-integrity manifest.
- A 50-language maintained catalog. Every Tier-1 language has baseline
  integration coverage; Tier 2 extends detection and generic scanning.
- PowerShell and POSIX entry points for Windows/Windows Server, Linux, macOS,
  and FreeBSD hosts. Android projects are scanned as source on a normal CI host.
- A public-safe baseline plus an ignored path for company policy, private rules,
  mirrors, and credentials.

## Five-minute start

Prerequisites are Python 3.11+ and either:

1. native installations of every enabled scanner; or
2. an approved runner image that contains Python, SecWeaver, and those native
   scanners.

Per-scanner container fallback exists for Gitleaks, Trivy, and OSV source
scans, but the current Opengrep adapter is native-only. A container engine by
itself therefore cannot satisfy the default balanced toolchain.

```sh
python3 -m pip install -e .
secweaver --config secweaver.toml doctor
secweaver --config secweaver.toml validate
secweaver --config secweaver.toml scan
```

From a source checkout, installation is optional:

```sh
./bin/secweaver --config secweaver.toml scan --dry-run
./scripts/security-ci.sh
```

On Windows:

```powershell
.\bin\secweaver.ps1 --config secweaver.toml scan --dry-run
.\scripts\security-ci.ps1
```

The Python wheel is intentionally the portable CLI runtime only. Use the source
repository or release archive for CI templates, policies, schemas, examples,
wrappers, and the complete documentation set. Before publishing the wheel to a
package index, set real source and documentation URLs in `pyproject.toml`.

Copy the closest file under [`templates/`](templates/) into a consumer
repository and pin the approved runner image by digest. Shipped pull-request
templates intentionally use locked built-in policy with
`--no-project-config`; they ignore a checkout-owned `secweaver.toml`. To
customize policy, edit the protected template to pass explicit trusted
`--config` paths, or remove that flag only where repository configuration is
itself trusted. The provider files deliberately stay thin so policy does not
drift between CI systems.

SecWeaver does not publish that all-in-one runner image in v0.1.0. The template
placeholder must be replaced with an image your project or organization builds,
scans, and approves; see [`containers/runner/`](containers/runner/).

## Pipeline model

| Stage | Runs on untrusted pull requests? | Purpose |
| --- | --- | --- |
| Validate | Yes | Parse configuration, resolve rules, and reject unsafe paths |
| Secret scan | Yes, without credentials | Scan the working tree and available Git history |
| Source and dependency scan | Yes, without credentials | Trivy, Opengrep, and OSV-Scanner |
| Normalize and decide | Yes | Redact, deduplicate, apply policy, and create reports |
| Publish reports | Provider-dependent | Upload short-lived artifacts with least privilege |
| Deploy verification | Protected refs only | Consume `verdict.json` before deployment |
| Deployment | Protected refs only | Remains owned by the deployment platform |

Argo CD is a deployment reconciler rather than a source CI runner. SecWeaver
therefore supplies an Argo CD verification hook and an Argo Workflows scan
template instead of pretending they are the same control.

## Default scanners

| Tool | Default role | Output consumed |
| --- | --- | --- |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Git history and working-tree secret detection | JSON, fully redacted before retention |
| [Trivy](https://trivy.dev/latest/docs/) | Vulnerabilities, misconfiguration, secrets, licenses, images | JSON and CycloneDX |
| [Opengrep](https://github.com/opengrep/opengrep) | Multi-language SAST using local reviewable rules | SARIF |
| [OSV-Scanner](https://google.github.io/osv-scanner/) | Lockfile and package vulnerability correlation | JSON |

The reviewed version snapshot is in
[`config/tools.lock.toml`](config/tools.lock.toml). Release pipelines should
replace example image tags with verified immutable digests. Strict policy
rejects mutable scanner images.

## Reports

By default, every non-dry-run scan writes a dedicated
`secweaver-reports/` directory:

| File | Audience |
| --- | --- |
| `summary.json` | Stable normalized machine-readable result |
| `verdict.json` | Small deployment gate contract |
| `summary.md` | Human review |
| `junit.xml` | CI test-report viewers |
| `results.sarif` | Code-scanning viewers |
| `sbom.cdx.json` | CycloneDX consumers |
| `report-manifest.json` | SHA-256 and size for each generated artifact |
| `raw/` | Sanitized reports from successfully parsed scanners; optional |
| `logs/` | Bounded redacted tails only when explicitly enabled; disabled by default |

The schemas are under [`schemas/`](schemas/). Scanner error, timeout,
unavailable tool, invalid report, clean scan, and findings are distinct states.
A missing required scanner never becomes a clean result.

Raw artifacts may still reveal package names or repository structure even after
redaction. Keep retention short, do not publish reports from private projects,
and set `reports.privacy = "strict"` to force raw and log retention off.

Exit codes:

| Code | Meaning |
| ---: | --- |
| 0 | Policy passed |
| 1 | Findings violated policy |
| 2 | Configuration or unsafe-path error |
| 3 | Required scanner or infrastructure failure |
| 4 | `doctor` found an incomplete required toolchain |

## Policy

Use multiple configuration files from general to specific; later files win:

```sh
secweaver \
  --config secweaver.toml \
  --config policies/strict.toml \
  --config secweaver.local.toml \
  scan
```

- `advisory` records results without blocking.
- `balanced` blocks critical/high findings, secrets, missing required scanners,
  and scanner failures.
- `strict` also blocks medium and misconfiguration findings and requires
  digest-pinned container images.
- `air-gapped.toml` selects native, offline execution and disables raw retention.

Environment overrides use the bounded `SECWEAVER_*` set documented in
[`docs/configuration.md`](docs/configuration.md); arbitrary environment keys
are not interpreted as configuration or commands.

An explicit global `--profile` is a policy lock: after configuration and
environment processing, SecWeaver re-applies that profile's blocking policy and
required-scanner set. The shipped CI templates also use
`--no-project-config`, so an untrusted checkout cannot silently supply its own
`secweaver.toml`. Edit the trusted template or pass a protected `--config`
overlay when repository-specific policy is required.

## Public repository and private-company use

The public repository contains no organization identifiers, network addresses,
credentials, private rules, or customer data. The default `.gitignore` excludes
`secweaver.local.toml` and `config/private/`.

A private deployment should:

1. keep the public baseline read-only or mirror it internally;
2. store a company overlay and rules in a private policy repository;
3. use CI-native secret stores only for jobs that truly require credentials;
4. mirror scanner databases and images, recording provenance and digests;
5. run pull-request scanning without secrets, write tokens, OIDC, privileged
   containers, or a mounted container socket;
6. allow report publishing and deployment only from protected refs;
7. review exclusions, baselines, suppressions, and tool updates like code.

See [`docs/enterprise.md`](docs/enterprise.md) and
[`docs/air-gapped.md`](docs/air-gapped.md).

## Language coverage

The catalog contains 50 languages. Tier 1 contains 20 priority languages:

TypeScript, Python, JavaScript, Java, C#, PHP, Shell, C++, HCL/Terraform, Go,
C, SQL, Rust, Kotlin, Ruby, Swift, Dart, R, Scala, and Lua.

For all 20, SecWeaver provides:

- deterministic repository detection;
- Gitleaks secret coverage independent of language;
- Trivy repository/filesystem coverage;
- OSV/Trivy dependency analysis where the ecosystem exposes supported package
  metadata;
- Opengrep execution with the bundled, original generic safety baseline;
- normalized reporting and the same policy gate.

That is 20/20 integration coverage, not 100% vulnerability detection. Some
languages and package formats have deeper scanner support than others.
Language-semantic SAST requires separately reviewed rules or an optional native
analyzer. The exact per-language evidence and limitations live in
[`docs/coverage.md`](docs/coverage.md) and
[`src/secweaver/data/languages.toml`](src/secweaver/data/languages.toml).

The maintained priority snapshot is informed by
[GitHub Octoverse 2025](https://github.blog/news-insights/octoverse/octoverse-2025/),
the [Stack Overflow 2025 Developer Survey](https://survey.stackoverflow.co/2025/technology/),
and [GitHub Linguist](https://github.com/github-linguist/linguist/blob/main/lib/linguist/languages.yml).
Popularity changes, so the dated method and lists are reviewable in
[`config/ranking-snapshot.toml`](config/ranking-snapshot.toml).

## Platform scope

| Platform | SecWeaver core | Scan target |
| --- | --- | --- |
| Linux | Python and POSIX wrapper | Source trees and OCI images |
| Windows / Windows Server | Python and PowerShell wrapper | Source trees; images when the engine supports them |
| macOS | Python and POSIX wrapper | Source trees; images through a local engine |
| FreeBSD | Python and POSIX wrapper | Source trees; complete native tool availability must be verified |
| Android | Run on a CI host, not an Android device | Android project source; APK/AAB analysis is not in v0.1.0 |

“Core supported” does not imply that every external scanner publishes a native
binary for every host. Use a hardened runner container or approved native
packages, then validate the exact version. See
[`docs/platforms.md`](docs/platforms.md) and
[`support-matrix.json`](support-matrix.json).

## Security boundaries

SecWeaver:

- passes argument arrays directly to processes with `shell=False`;
- resolves source, report, catalog, and rule paths inside the workspace;
- refuses to replace an arbitrary non-empty report directory;
- runs container scanners read-only with dropped capabilities,
  `no-new-privileges`, bounded temporary filesystems, and optional no-network
  mode;
- uses a minimal allowlisted environment and an isolated runtime home;
- strips common secret-bearing fields, code snippets, absolute paths, and
  credential-shaped log text;
- caps report size and rejects symlink or malformed scanner reports.

CI templates cannot protect a repository from unsafe changes made to the
templates themselves. Protect the default branch, require review of pipeline
files and rules, pin actions/images, and separate untrusted PR scanning from
credentialed release jobs. Report security defects through
[`SECURITY.md`](SECURITY.md).

## Extend it

To add a scanner:

1. add a typed `ScannerDefinition` builder in
   [`src/secweaver/scanners.py`](src/secweaver/scanners.py);
2. add a bounded parser and raw-report sanitizer in
   [`src/secweaver/reports.py`](src/secweaver/reports.py);
3. define clean/findings/error behavior and policy applicability;
4. add malicious-path, malformed-report, redaction, and parser fixtures;
5. document license, provenance, supported targets, and output schema changes.

Do not add a configuration field that executes an arbitrary command. New tools
must receive a reviewed adapter.

## Development

```sh
make validate
make test
PYTHONPATH=src python scripts/validate_repository.py
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md), [`docs/architecture.md`](docs/architecture.md),
and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
