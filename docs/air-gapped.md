# Air-gapped operation

SecWeaver can orchestrate locally available scanners without normal internet
access, but `offline = true` is not a complete air-gap installation. Tools,
rules, container images, package metadata, and vulnerability databases must be
prepared before the disconnected scan.

## What offline mode currently changes

When `scan.offline = true`:

- execution must be `native`;
- `offline.home_dir`, `offline.trivy_cache_dir`, and
  `offline.osv_database_path` must name existing directories inside the
  workspace;
- the Trivy and OSV directories must be distinct, must not overlap the report
  directory, and must each contain at least one regular non-symlink file;
- Trivy receives the configured `--cache-dir`, `--offline-scan`,
  `--skip-db-update`, `--skip-java-db-update`, and `--skip-check-update`;
- OSV-Scanner receives `--offline-vulnerabilities` and the configured
  `--local-db-path`;
- Opengrep continues to use configured local rule files;
- Gitleaks continues to scan local files or local Git history.

SecWeaver does not add an offline flag to Gitleaks or Opengrep because the
implemented commands use local targets and rules.

The native-only requirement is intentional in v0.1.0: the current container
adapters do not provide reviewed, read-only mounts for preseeded Trivy and OSV
databases, and Opengrep has no container adapter.

Native scanner processes are not placed in an operating-system network
sandbox by SecWeaver. For a guaranteed disconnected execution environment,
enforce egress controls at the runner, VM, jail, or network layer in addition
to selecting offline mode.

The structural directory checks do not validate database schema, signature,
digest, completeness, or freshness. Enforce those properties in the transfer
and runner-provisioning process described below.

## Required offline inventory

Prepare and approve:

- the SecWeaver source archive or Python wheel;
- Python 3.11+ for each runner platform;
- Gitleaks, Trivy, Opengrep, and OSV-Scanner binaries for each required
  OS/architecture;
- the Trivy vulnerability database;
- the Trivy Java vulnerability database when Java scanning requires it;
- the Trivy misconfiguration checks bundle when a newer approved bundle is
  required;
- OSV offline vulnerability databases;
- all Opengrep rules referenced by configuration;
- organization TOML overlays and schemas;
- internal CA certificates, if required;
- checksums, signatures, license notices, source URLs, versions, and retrieval
  timestamps.

Gitleaks does not require a vulnerability database. Its rules still need to be
versioned and reviewed with the selected binary.

Trivy documents its network dependencies, self-hosted OCI databases, and manual
cache population:

- [Connectivity and air-gap considerations](https://trivy.dev/docs/latest/advanced/air-gap/)
- [Self-hosting Trivy databases](https://trivy.dev/docs/latest/guide/advanced/self-hosting/)

OSV-Scanner documents offline vulnerability databases and notes that some
online dependency-resolution behavior is unavailable offline:

- [OSV-Scanner usage](https://google.github.io/osv-scanner/usage/)
- [Supported artifacts and manifests](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)

## Recommended transfer process

### Connected preparation environment

1. Resolve exact approved versions.
2. Download from authoritative upstream release locations.
3. Verify upstream checksums and signatures where available.
4. Pull OCI images by digest rather than mutable tag.
5. Download vulnerability databases and record their metadata.
6. Collect locally maintained and third-party rules with their individual
   licenses;
7. generate an inventory containing filename, source URL, version, license,
   SHA-256 digest, architecture, and retrieval time;
8. sign the inventory with the organization's approved process;
9. copy the bundle to approved transfer media or an internal staging registry.

### Disconnected environment

1. Verify the signed inventory before import.
2. Recompute every file and image digest.
3. Load images into the internal registry or engine.
4. place vulnerability databases in the scanner-specific cache locations;
5. install native binaries without a network bootstrap script;
6. set configuration to local rules and mirrors;
7. run `secweaver doctor`;
8. run `secweaver validate`;
9. run a safe positive and clean conformance fixture;
10. run the real scan with offline mode.

Do not transfer registry credentials, private signing keys, or active tokens as
part of the public or reusable scanner bundle.

## Example offline overlay

```toml
[scan]
execution = "native"
offline = true
required_scanners = ["gitleaks", "trivy", "opengrep", "osv"]
sast_rule_paths = [
  "builtin:baseline",
  ".offline-rules/organization.yml",
]

[offline]
home_dir = ".secweaver-offline/home"
trivy_cache_dir = ".secweaver-offline/trivy-cache"
osv_database_path = ".secweaver-offline/osv-db"

[policy]
missing_required_tool = "fail"
scanner_error = "fail"

[reports]
privacy = "strict"
retain_raw = false
retain_logs = false
```

Create and populate all three offline directories before validation. SecWeaver
will not download or initialize their contents.

The same setting can be enabled with `--offline` or
`SECWEAVER_OFFLINE=true`, but the other native-execution and directory
requirements still apply. Trusted CI should control those values.

## Container image caveat

The default tool configuration names version tags. Tags improve
reproducibility compared with `latest`, but they are not immutable digests.
The strict profile rejects non-digest-pinned scanner images when SecWeaver
selects container execution.

An organization using container execution outside enforced offline mode should
override image references with mirrored `@sha256:` references. This applies to
the images used to execute scanners. The OCI image selected as the scan target
should also be supplied by digest by the calling release process.

## Database freshness

Offline scans are only as current as their databases and rules. Record at least:

- database build or publication time;
- import time;
- scanner version;
- database schema version;
- rule bundle version and digest;
- maximum permitted age;
- whether a database update failed.

Choose a documented response for stale data:

- fail closed for release;
- warn for advisory scanning;
- allow a time-limited, reviewed exception.

Do not silently label a stale-database scan as current.

## Known degraded behavior

- Trivy's `--offline-scan` prevents remote package lookups such as Maven Central
  enrichment. Identification can be less complete.
- OSV-Scanner offline mode uses cached databases and disables functionality
  that requires online resolution.
- A vulnerability absent from the imported database cannot be reported.
- A source dependency without a supported manifest or lockfile can be missed.
- The built-in Opengrep baseline is small and intentionally does not download a
  remote ruleset.
- Scanner installation support on a runner OS does not imply full target-OS
  vulnerability coverage.

These limitations should appear in the report or accompanying evidence for a
regulated release.

## Testing the disconnected path

An air-gap test should prove:

- no DNS or external network access is available;
- every required scanner is found;
- every required database loads;
- both a known positive and a known clean fixture behave as expected;
- report generation completes after policy failure;
- reports contain no secret values or absolute source paths;
- database-age policy produces the intended result.

Do not claim an air-gapped configuration is verified solely because the TOML
file contains `offline = true`.
