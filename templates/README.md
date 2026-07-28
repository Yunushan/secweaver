# CI/CD adapter templates

These files are deliberately thin adapters around one trusted command. Copy the
nearest template into a consumer repository, review it against the exact CI
product and runner version, and keep policy in the SecWeaver core.

## Required runner image

`YOUR_RUNNER_IMAGE@sha256:REPLACE_WITH_DIGEST` is a mandatory placeholder, not a
published image. Replace it with an approved, digest-pinned image containing:

- Python 3.11 or later;
- the SecWeaver package;
- Gitleaks 8.30.1;
- Trivy 0.72.0;
- Opengrep 1.26.0;
- OSV-Scanner 2.4.0.

The templates select native scanner execution inside that image. This is
necessary because the current Opengrep adapter has no container fallback. Build
and scan the image in your own release process, record upstream checksums and
licenses, and update the digest only through review.

Kubernetes templates run as numeric UID/GID `65532`. The runner image must
support that identity, and Tekton callers must provide a workspace writable by
it. The Argo templates set `fsGroup: 65532` for their ephemeral volumes.
The Argo Workflows template also references a dedicated
`secweaver-workflow-executor` ServiceAccount because automatic token mounting is
disabled. A cluster administrator must create it with only the executor
permissions required by the installed Argo version; do not grant those
permissions to the scanner container.

## Trust contract

The public templates:

- run without user-provided secrets or deployment credentials;
- give repository content read-only platform permissions where supported;
- use `--no-project-config` so an untrusted checkout cannot provide
  `secweaver.toml`;
- use `--profile balanced` or another trusted, validated profile;
- write into a fresh `secweaver-reports` directory;
- preserve reports after a nonzero scan exit where the provider supports it;
- keep deployment separate from source scanning.

If a company needs repository-specific settings, replace
`--no-project-config` with explicit protected `--config` paths and keep a
trusted `--profile` lock. Control every `SECWEAVER_*` variable, rule path,
scanner suppression file, and later CLI argument in the protected template.

## Evidence level

The checked-in files are editable reference templates. The dependency-free
repository validator checks their required trust-contract fragments, and the
v0.1.0 release audit parsed every YAML document locally. Provider-specific
schema lint and hosted execution remain pending. Similar workflow syntax is not
proof of behavioral compatibility.

| Template | Intended product | Current evidence |
| --- | --- | --- |
| `github/security.yml` | GitHub Actions | Contract check + local YAML parse |
| `gitlab/security.yml` | GitLab CI/CD | Contract check + local YAML parse |
| `gitea/security.yml` | Gitea Actions | Contract check + local YAML parse |
| `forgejo/security.yml` | Forgejo Actions | Contract check + local YAML parse |
| `bitbucket/bitbucket-pipelines.yml` | Bitbucket Pipelines | Contract check + local YAML parse |
| `woodpecker/security.yml` | Woodpecker CI | Contract check + local YAML parse |
| `drone/.drone.yml` | Drone CI | Contract check + local YAML parse |
| `jenkins/Jenkinsfile` | Jenkins Pipeline | Contract check + manual review |
| `azure/azure-pipelines.yml` | Azure Pipelines | Contract check + local YAML parse |
| `circleci/config.yml` | CircleCI | Contract check + local YAML parse |
| `tekton/security-pipeline.yml` | Tekton Pipelines v1 | Contract check + local YAML parse |
| `argo-workflows/security-workflowtemplate.yml` | Argo Workflows | Contract check + local YAML parse |
| `argo-cd/presync-security-gate.yml` | Argo CD/Kubernetes | Contract check + local YAML parse |

Provider-specific action, plug-in, artifact, and runner versions must be pinned
and tested on the target installation before enforcement. The Gitea and Forgejo
templates intentionally leave full action commit placeholders because the
compatible commit depends on the deployed product version.
