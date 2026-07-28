# SecWeaver runner image contract

CI templates use `YOUR_RUNNER_IMAGE@sha256:REPLACE_WITH_DIGEST` intentionally.
SecWeaver does not publish an unreviewed all-in-one image from this source
archive.

An organization or release maintainer can build a runner image that contains:

- Python 3.11+ and the SecWeaver wheel;
- the exact Gitleaks, Trivy, Opengrep, and OSV-Scanner releases recorded in
  `config/tools.lock.toml`;
- license texts, an image SBOM, release checksums, and build provenance;
- an unprivileged default user and a writable `/reports` directory.

The release process should scan the image, sign it, record its immutable digest,
and test that:

```sh
secweaver --version
gitleaks version
trivy --version
opengrep --version
osv-scanner --version
```

Downstream CI should reference only the approved digest. Do not mount a
container-engine socket or run this image privileged. Scanner containers run by
the local orchestrator are an alternative when the CI job itself has a
carefully controlled engine; they are not appropriate for untrusted jobs with
a shared host socket.
