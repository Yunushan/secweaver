# Scanner catalog

<!-- markdownlint-disable MD013 -->

SecWeaver currently integrates four scanner engines and one Trivy-based SBOM
task. The versions below are the configured defaults in this source tree, not a
promise that a runner has installed them or that a remote tag still resolves to
the same content.

## Core scanners

| Adapter | Configured version | Primary role | Targets | Native | Container adapter |
| --- | ---: | --- | --- | --- | --- |
| Gitleaks | 8.30.1 | Secret detection in files or Git history | Source | Yes | Yes |
| Trivy | 0.72.0 | Vulnerabilities, misconfigurations, secrets, and licenses | Source and image | Yes | Yes |
| Opengrep | 1.26.0 | Rule-driven SAST | Source | Yes | No |
| OSV-Scanner | 2.4.0 | Dependency vulnerability matching | Source and image | Yes | Source only |
| Trivy SBOM | Trivy 0.72.0 | CycloneDX inventory | Source and image | Yes | Yes |

`secweaver doctor` checks whether native commands are discoverable and reports
the configured container reference. Before a native scan, SecWeaver invokes the
tool's version command and fails that scanner if the reported version does not
match the exact configured version. Container mode records the configured
version, so image provenance and digest verification remain the caller's
responsibility.

## Gitleaks

SecWeaver uses:

- `gitleaks git` when history scanning is enabled;
- `gitleaks dir` when history scanning is disabled;
- JSON report output;
- `--redact=100`;
- scanner exit code zero so SecWeaver, rather than the scanner, applies policy.

Gitleaks is language-independent and source-only in the current adapter. Git
history coverage depends on the checkout containing the intended commits; a
shallow CI checkout cannot provide absent history.

The Gitleaks project states that it is feature-complete and expects future
releases to focus on security fixes. Keep the adapter boundary replaceable and
review upstream status when upgrading:
[Gitleaks](https://github.com/gitleaks/gitleaks).

Gitleaks is MIT-licensed at the referenced upstream repository. Preserve its
license when distributing the binary or image.

Betterleaks may be evaluated as an optional future adapter. Its active-secret
validation can make network requests containing a detected candidate, so
validation must be disabled by default and separately approved for private
code.

## Trivy

SecWeaver requests these scanners from Trivy:

- `vuln`;
- `misconfig`;
- `secret`;
- `license`.

It uses `trivy filesystem` for source and `trivy image` for OCI images. A
separate invocation creates CycloneDX JSON.

Trivy is broad but not universal. Its result depends on:

- supported operating systems and language ecosystems;
- package and lockfile metadata;
- artifact visibility;
- vulnerability database age;
- Java or other enrichment sources;
- checks bundle and policy configuration.

Installation support on Windows or FreeBSD is not the same as complete
Windows or FreeBSD target-OS vulnerability coverage. Consult the pinned
version's official coverage documentation:
[Trivy documentation](https://trivy.dev/docs/latest/).

Trivy is Apache-2.0 licensed at its upstream repository. Its databases and
checks also need their own provenance and redistribution review.

## Opengrep

SecWeaver invokes Opengrep natively and consumes SARIF 2.1.0. Rules are supplied
only through configured paths. The default `builtin:baseline` points to the
small SecWeaver-owned 0BSD rule file shipped with the Python package.

The baseline is a portable safety net. It does not provide comprehensive
framework, cross-file, or language-specific vulnerability coverage.

Opengrep lists more than 30 parsed languages and produces JSON and SARIF:
[Opengrep](https://github.com/opengrep/opengrep). The engine is LGPL-2.1.
Engine licensing does not grant rights to every compatible rule pack. Track the
source and license of each imported rule.

The current adapter has no container arguments. `execution = "container"`
therefore makes required Opengrep unavailable. Native or automatic execution
with an installed binary is required until a tested container adapter is added.

Semgrep CE is not a current core adapter. Semgrep-compatible syntax does not
make Semgrep-maintained rules 0BSD. Semgrep documents a separate restrictive
license for its maintained rules:
[Semgrep licensing](https://docs.semgrep.dev/licensing).

## OSV-Scanner

SecWeaver uses recursive source scanning for repositories and image scanning
for OCI image targets. It consumes OSV JSON and groups aliases when the report
provides them.

Coverage depends on supported lockfiles, extracted packages, ecosystem
identifiers, resolution behavior, and OSV database contents. A catalog entry
declaring an ecosystem is not proof that every manifest variant is supported.

Offline mode uses cached offline databases and can lose online transitive
resolution behavior. Review:

- [OSV-Scanner usage](https://google.github.io/osv-scanner/usage/)
- [Supported artifacts and manifests](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)

OSV-Scanner is Apache-2.0 licensed at its upstream repository. Preserve its
notices and review the data licenses used in an offline mirror.

## Overlap and normalization

Scanner overlap is intentional:

- Gitleaks and Trivy can both report secrets.
- Trivy and OSV-Scanner can both report dependency vulnerabilities.
- Opengrep and Trivy can both report configuration-related source patterns.

SecWeaver preserves scanner identity and creates stable fingerprints where
possible. It does not currently perform a global CVE/GHSA/OSV alias
deduplication across scanners. Counts can therefore include multiple evidence
records for one underlying issue.

Policy should not assume that a larger count always means more distinct
vulnerabilities.

## Optional ecosystem analyzers

These are recommended extension candidates, not implemented core adapters:

| Ecosystem | Examples | Purpose |
| --- | --- | --- |
| JavaScript/TypeScript | ESLint security rules | Language/framework lint and SAST |
| Python | Bandit | Python security patterns |
| Java/JVM | SpotBugs + FindSecBugs | Bytecode and security analysis |
| .NET | Roslyn analyzers | Compiler-integrated analysis |
| C/C++ | Clang Static Analyzer, clang-tidy, cppcheck | Native code analysis |
| Go | gosec, govulncheck | Source patterns and Go vulnerability data |
| Rust | Clippy, cargo-audit, cargo-deny | Correctness, vulnerabilities, policy |
| Ruby | Brakeman, bundler-audit | Rails SAST and dependency advisories |
| Shell | ShellCheck | Shell correctness and risky constructs |
| Terraform | TFLint, `terraform validate` | Provider and configuration validation |
| Kubernetes/Helm | kube-linter, Helm lint, Conftest | Manifest and policy validation |
| Android | Android Lint, MobSF | Android source and APK/AAB analysis |
| Web DAST | OWASP ZAP | Authorized dynamic testing |

An optional analyzer becomes a supported SecWeaver integration only after it
has:

1. an exact version and license record;
2. safe native or container command construction;
3. positive and clean fixtures;
4. a bounded timeout;
5. a report parser;
6. secret and path sanitization;
7. policy behavior for missing/error states;
8. platform evidence;
9. documentation of limitations.

## Optional licensed integrations

CodeQL can add deeper analysis for its supported languages, but it is not
vendor-neutral, not a top-50 engine, and is not part of the default stack.
GitHub documents that public and private repository use have different
availability and licensing:
[CodeQL CLI](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli).

SonarQube, commercial SAST products, DefectDojo, Dependency-Track, and
provider-native security dashboards can be downstream integrations. They
should remain optional and must not be required to use SecWeaver's public
baseline.

## Version and supply-chain policy

For every scanner upgrade:

- review the changelog and breaking report-schema changes;
- verify checksum or signature;
- update the configured version;
- pin container images by digest for strict/release use;
- run positive, clean, malformed-report, timeout, and redaction tests;
- review engine, image, database, and rule licenses independently;
- record the database/rules timestamp;
- update `THIRD_PARTY_NOTICES.md` when required.

Version tags are mutable references. The default configuration uses explicit
version tags for convenience, while the strict profile requires immutable
scanner image references when container execution is selected.

## Adding a core scanner

The current scanner list is explicit rather than dynamically discovered.
Adding one requires coordinated changes to:

- default and validated configuration;
- scanner command definition;
- target applicability;
- native/container selection;
- raw report parsing;
- redaction;
- normalized categories and severities;
- required-tool and error policy;
- `doctor` output;
- report fixtures and tests;
- license and limitation documentation.

Avoid adding a scanner only by copying a CI command. Without parsing,
sanitization, policy, and tests, it is an external CI step rather than a
SecWeaver core integration.
