# Private-company integration

<!-- markdownlint-disable MD013 -->

SecWeaver is intended to remain safe for a public 0BSD repository while allowing
a private organization to apply stricter policy, private rules, internal
registries, and private report handling.

The public repository should remain usable without any company-specific data.

## Public/private boundary

Keep these public:

- SecWeaver source and tests;
- generic CI templates;
- scanner adapter definitions;
- synthetic non-secret fixtures;
- the small SecWeaver-owned baseline rules;
- example policy files using placeholder values;
- documentation and schemas.

Keep these private:

- internal domains, IP addresses, repository names, and registry paths;
- employee or customer data;
- real credentials, certificates, signing keys, and tokens;
- internal vulnerability exceptions;
- private package names and SBOMs;
- organization-specific threat models and rules;
- security reports, unless explicitly approved for publication.

Do not “encrypt and commit” a secret to the public repository as a general
configuration mechanism. Use the company's CI secret store, an approved secret
manager, workload identity, or a separately controlled private repository.

## Layered configuration

Pass the repository configuration first and the organization overlay last:

```console
secweaver \
  --config secweaver.toml \
  --config .company-security/secweaver-policy.toml \
  --profile strict \
  scan
```

Global options must appear before the `scan` subcommand.

Later configuration files normally override earlier files. An explicit
`--profile` is re-applied last and locks that profile's full policy table and
required-scanner set. It does not lock every scan input. The trusted CI template
must still control:

- which configuration paths are loaded;
- their order;
- `SECWEAVER_PROFILE`;
- `SECWEAVER_SCANNERS` and `SECWEAVER_REQUIRED_SCANNERS`;
- `SECWEAVER_FAIL_ON` and `SECWEAVER_FAIL_CATEGORIES`;
- `SECWEAVER_SAST_RULE_PATHS`;
- target, execution, history, offline, and SBOM overrides.

For an untrusted pull request that needs no repository-specific settings, use
the shipped template model:

```console
secweaver --no-project-config --profile balanced scan --target .
```

This suppresses `secweaver.toml` discovery and locks the balanced policy.
`--no-project-config` and `--config` are mutually exclusive. The current core
does not cryptographically verify organization policy, so enforce the remaining
boundary in template permissions, branch protection, and runner configuration.

## Example private overlay

An overlay contains policy and non-secret locations, not credentials:

```toml
[scan]
profile = "strict"
required_scanners = ["gitleaks", "trivy", "opengrep", "osv"]
history = true
generate_sbom = true
sast_rule_paths = [
  "builtin:baseline",
  ".company-security/rules/application-security.yml",
]

[policy]
fail_on_severities = ["CRITICAL", "HIGH", "MEDIUM"]
fail_on_categories = ["secret", "misconfiguration"]
missing_required_tool = "fail"
scanner_error = "fail"
require_immutable_images = true

[reports]
privacy = "strict"
retain_raw = false
retain_logs = false
include_absolute_paths = false
```

Paths and settings must match the actual checkout layout. Validate the composed
configuration before scanning:

```console
secweaver \
  --config secweaver.toml \
  --config .company-security/secweaver-policy.toml \
  --profile strict \
  validate
```

Strict report privacy forces normalized raw and scanner-log retention off.
Summaries, the SBOM, and manifest can still reveal private metadata and require
private artifact controls.

## Policy profiles

| Profile | Intended starting point | Current default behavior |
| --- | --- | --- |
| Advisory | Evaluation and initial rollout | Does not block on findings; missing/error scanners warn |
| Balanced | Normal pull-request and branch protection | Blocks high/critical findings and all secret-category findings; core scanners required |
| Strict | Release or regulated environment baseline | Also blocks medium findings and misconfigurations; requires immutable scanner images in container mode |

Profiles are starting points, not compliance certifications. An organization
must review severities, categories, tool failure behavior, exemptions, and
retention against its own threat model.

## Recommended job separation

### Untrusted pull request

- use read-only repository permissions;
- expose no production or deployment credentials;
- prefer ephemeral runners;
- scan the changed checkout;
- avoid executing package install hooks unless the build job is separately
  sandboxed;
- upload sanitized reports to restricted artifact storage.

The current `scan.history` option selects full Git history or a directory scan.
SecWeaver does not yet implement a first-class “new findings versus base branch”
policy. A calling CI workflow must manage diff-oriented behavior and baselines.

SecWeaver supplies scanner-owned Gitleaks, Trivy, Opengrep, and OSV control
files and disables their repository-native ignore mechanisms where the pinned
CLI supports it. Trivy suppressed findings are converted into a blocking
misconfiguration finding. Protect and review pipeline files, SecWeaver TOML,
and explicit rule paths anyway: scanner flags and suppression semantics remain
version-specific, and a future adapter must preserve this boundary.

### Protected branch or scheduled scan

- fetch the intended Git history;
- refresh approved vulnerability databases;
- use the reviewed organization overlay;
- scan all intended source and image targets;
- retain evidence according to policy;
- route findings to the approved private system.

### Release

- scan the exact immutable artifact intended for release;
- retain source and artifact results separately;
- require all mandatory scanners to complete;
- create signing and provenance attestations in a separate, controlled step;
- promote by digest, not a mutable tag.

SecWeaver currently creates reports and an SBOM but does not sign artifacts or
generate SLSA provenance.

## Private registries and air gaps

Scanner image or database credentials must come from the CI platform or runner,
not TOML committed to a repository. Prefer short-lived workload identity over
long-lived passwords. Public and pull-request templates intentionally pass no
registry authentication.

For a protected native-execution job, a private overlay may explicitly add
`DOCKER_CONFIG` to `environment.passthrough`. Point it at a temporary,
access-controlled Docker configuration directory created by the CI secret
store, outside the checkout, and destroy it after the job. This enables native
Trivy to use reviewed registry authentication without putting credentials in
TOML. Container-mode target scanning does not mount that configuration into a
scanner container in v0.1.0; use approved native execution for private target
registries or add and review a company-specific adapter.

For restricted networks:

- mirror scanner images by digest;
- mirror native scanner binaries and verify their checksums;
- host approved rules and vulnerability databases internally;
- provide the organization's CA trust through runner configuration;
- record update timestamps and reject stale databases according to policy.

See [air-gapped.md](air-gapped.md) for the behavior and limitations of
SecWeaver's offline mode.

## Findings and report privacy

Even after source snippets and obvious secrets are redacted, reports can expose:

- private package names and versions;
- repository structure and filenames;
- vulnerability and policy exceptions;
- operating-system details;
- scanner and toolchain versions;
- internal artifact references.

Use access-controlled artifact storage, short retention where appropriate,
encryption at rest, audit logging, and restricted downstream integrations.
Avoid uploading private findings to a public security dashboard.

## GitOps and Argo CD

Argo CD should consume an approved Git state after CI. It should not receive
source-scanner responsibilities or broad build credentials.

A recommended enterprise flow is:

1. SecWeaver scans source and the selected artifact.
2. CI evaluates policy and retains the evidence.
3. A separate signing step signs the immutable artifact and attestations.
4. CI or a release process proposes the digest to a private GitOps repository.
5. Review and policy approve the GitOps change.
6. Argo CD reconciles the approved state.
7. Admission controls verify signatures and deployment policy where configured.

This is reference architecture. The current SecWeaver Python core does not
modify GitOps repositories, call Argo CD, or manage rollback.

## License and tool governance

The 0BSD license applies to SecWeaver-owned material only.

- Preserve notices and licenses for scanner binaries and images.
- Record licenses in `THIRD_PARTY_NOTICES.md` or equivalent inventory.
- Review rule-pack licenses separately from engine licenses.
- Do not copy Semgrep-maintained rules into the 0BSD rule directory. Semgrep
  documents separate terms for its maintained rules:
  [Semgrep licensing](https://docs.semgrep.dev/licensing).
- Treat CodeQL as an optional licensed integration. GitHub documents different
  availability for public and private repositories:
  [CodeQL CLI](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli).
- Re-run license review when a tool, image, database, or ruleset is upgraded.
