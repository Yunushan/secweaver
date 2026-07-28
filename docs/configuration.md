# Configuration reference

SecWeaver starts with built-in defaults, merges each explicit TOML file in
command-line order, applies the bounded environment overrides below, and then
applies explicit scan-command options. A global `--profile` lock is re-applied
last to restore that built-in profile's policy table and required scanners.

Use `--no-project-config` for untrusted checkouts. Without that option or an
explicit `--config`, SecWeaver loads `secweaver.toml` from the current
workspace when it exists.

## Environment overrides

Only these `SECWEAVER_*` variables alter configuration:

| Variable | Configuration field | Value |
| --- | --- | --- |
| `SECWEAVER_PROFILE` | `scan.profile` | `advisory`, `balanced`, or `strict` |
| `SECWEAVER_TARGET` | `scan.target` | Workspace-relative directory |
| `SECWEAVER_TARGET_KIND` | `scan.target_kind` | `source` or `image` |
| `SECWEAVER_IMAGE` | `scan.image` | OCI reference |
| `SECWEAVER_EXECUTION` | `scan.execution` | `auto`, `native`, or `container` |
| `SECWEAVER_CONTAINER_ENGINE` | `scan.container_engine` | `docker` or `podman` |
| `SECWEAVER_REPORT_DIR` | `scan.report_dir` | Workspace-relative directory |
| `SECWEAVER_SCANNERS` | `scan.enabled_scanners` | Comma-separated scanner names |
| `SECWEAVER_REQUIRED_SCANNERS` | `scan.required_scanners` | Comma-separated scanner names |
| `SECWEAVER_FAIL_ON` | `policy.fail_on_severities` | Comma-separated severities |
| `SECWEAVER_FAIL_CATEGORIES` | `policy.fail_on_categories` | Comma-separated categories |
| `SECWEAVER_SAST_RULE_PATHS` | `scan.sast_rule_paths` | Comma-separated rule paths |
| `SECWEAVER_OFFLINE` | `scan.offline` | Boolean |
| `SECWEAVER_HISTORY` | `scan.history` | Boolean |
| `SECWEAVER_GENERATE_SBOM` | `scan.generate_sbom` | Boolean |
| `SECWEAVER_RETAIN_RAW` | `reports.retain_raw` | Boolean |

Boolean values accept `1`, `true`, `yes`, or `on`, and `0`, `false`, `no`, or
`off`, case-insensitively. Empty comma-separated items are removed. All final
values still pass the same configuration validation as TOML.

## Scanner environment

`environment.passthrough` is separate from configuration overrides. It controls
which names from a fixed safe allowlist can reach scanner processes. SecWeaver
always builds a reduced process environment and replaces scanner home/cache
paths. Public templates use no registry credentials.

Protected native-execution jobs can explicitly pass `DOCKER_CONFIG` for private
registry access as described in [enterprise.md](enterprise.md). Never enable
credential-bearing paths or variables for untrusted pull requests.

## Schemas and examples

- [`secweaver-config.schema.json`](../schemas/secweaver-config.schema.json)
  mirrors the supported TOML structure.
- [`secweaver.toml`](../secweaver.toml) is the public default.
- [`examples/`](../examples/) contains minimal, monorepo, enterprise, and
  offline overlays.
- [`policies/`](../policies/) contains the built-in policy starting points in
  editable TOML form.
