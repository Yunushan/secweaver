# Platforms and execution environments

<!-- markdownlint-disable MD013 -->

SecWeaver is designed to separate where a scan runs from what it scans. A
platform claim must identify the runner, target, source language, and artifact
type.

## Terminology

| Term | Question answered |
| --- | --- |
| Runner OS | Where does Python start the scanner process? |
| Target OS | Which operating system will use or contain the software? |
| Source language | Which source files and dependency manifests are present? |
| Artifact | Is the target a source tree, image, APK, AAB, archive, or SBOM? |

Examples:

- A Linux runner can scan a Windows-targeted .NET source tree.
- A macOS runner can scan a Linux OCI image.
- An Android project is normally scanned on Linux, macOS, or Windows; Android
  is the target platform, not the CI runner.
- Successful execution of Trivy on FreeBSD does not prove that Trivy has a
  complete FreeBSD operating-system advisory database.

## Core runtime

The Python package requires Python 3.11 or later and has no runtime Python
dependencies. Scanner executables remain separate.

SecWeaver supports three execution selections:

- `native`: require scanner executables on the runner;
- `container`: require a container engine and an implemented container adapter;
- `auto`: prefer a native executable, otherwise use an implemented container
  adapter.

The current Opengrep adapter has no container command. Use native or automatic
execution with an installed Opengrep binary when Opengrep is required.

Container execution currently applies a read-only container root, dropped
capabilities, `no-new-privileges`, temporary filesystems, a read-only source
mount, and a writable report mount. These flags are designed around
Docker-compatible command syntax. Another engine should be considered
supported only after its command behavior is tested.

## Runner matrix

| Runner | Intended use | Current confidence boundary |
| --- | --- | --- |
| Linux | Primary native or container scan environment | Core design target; exact distribution and architecture still need recorded tests |
| Windows desktop | Native Python and scanner execution | Requires compatible scanner binaries and path testing |
| Windows Server | Self-hosted native execution and Windows-specific builds | Do not claim all Server releases; record each tested version |
| macOS | Native scans and Apple toolchain jobs | Xcode-dependent checks require an installed, selected Xcode version |
| FreeBSD | Native Python scans and FreeBSD-native build validation | Each scanner/package version needs its own compatibility evidence |
| Android | Not a normal Python runner target for this project | Treat as source and APK/AAB target support |

The package metadata advertises Linux, Windows, macOS, and FreeBSD intent.
Metadata is not a test report.

## Linux

Linux is the simplest environment for portable scanner containers. It is the
recommended runner for repository scans, Linux OCI images, Terraform and
Kubernetes configuration, and Android builds.

Container jobs must still:

- pin or mirror images according to the selected policy;
- control access to the container engine;
- avoid exposing a privileged Docker socket to untrusted code;
- provide enough temporary storage for vulnerability databases;
- retain the SecWeaver report directory after a nonzero exit.

## Windows and Windows Server

Prefer native execution when scanning Windows-hosted workspaces. Linux scanner
images do not automatically run in Windows container mode.

For a Windows or Windows Server claim, record:

- Windows edition and build;
- Python version;
- shell used to invoke SecWeaver;
- filesystem and path behavior;
- native scanner versions;
- whether Git history was available;
- whether source or image targets were tested.

“Windows Server support” must not be used as shorthand for every Windows Server
release. Server 2016, 2019, 2022, and 2025 have different lifecycle and toolchain
constraints and need separate evidence.

Windows source scanning also does not imply complete Windows Update, KB, MSI,
or Windows container base-image vulnerability coverage.

## macOS

Native SecWeaver execution can orchestrate compatible scanner binaries on
macOS. Swift and Objective-C source checks may run on other systems, but a
native Apple build, Xcode analyzer, signing check, or framework resolution
normally requires macOS and Xcode.

Record CPU architecture separately. A successful Apple silicon run does not
automatically verify an Intel runner, or the reverse.

## FreeBSD

FreeBSD can run the Python core when Python 3.11+ and compatible scanner tools
are installed. Trivy documents an official FreeBSD package installation:
[Trivy installation](https://trivy.dev/docs/latest/getting-started/installation/).

Scanner installation support and vulnerability coverage are different facts.
Trivy's documented operating-system vulnerability coverage lists specific
operating systems and distributions; do not infer full FreeBSD base-system or
ports coverage from the availability of a FreeBSD package.

If a language analyzer does not run on FreeBSD, a defensible pattern is:

1. run source-only portable scanners on a verified Linux runner;
2. run the actual FreeBSD build and native tests on FreeBSD;
3. label the two results separately.

Do not report that the Linux scanner ran “on FreeBSD.”

## Android

Android coverage is a composition of:

- Java/Kotlin or other source-language scans;
- Gradle and supported lockfile/dependency analysis;
- Android Lint or another optional ecosystem analyzer;
- scanning of the built APK or AAB with an explicitly integrated mobile
  analyzer.

The current SecWeaver core detects and scans repository content, but does not
build APK/AAB files or invoke MobSF. Those steps are optional CI stages until an
adapter and tests are added.

An Android emulator is not required for static source or artifact scanning.
Dynamic mobile testing is a separate, explicitly authorized stage.

## OCI images

`scan.target_kind = "image"` makes Trivy and OSV-Scanner applicable and skips
source-only Gitleaks and Opengrep. Trivy can also generate the CycloneDX SBOM
for the image. The current OSV image adapter is native-only, so container-only
execution cannot run that required scan.

Use immutable digest references for release decisions. The strict policy
requires digest-pinned container images used to execute scanners, but the image
being scanned should also be selected by digest in the calling pipeline.

Image scanners only report what their catalogers and vulnerability sources can
identify. A clean result is not proof that the base operating system, bundled
firmware, manually copied binary, or application behavior is vulnerability-free.

## CI products

SecWeaver's Python core is CI-neutral. Provider support has several possible
levels:

1. a syntactically valid example;
2. a locally linted or schema-validated template;
3. a real run on a named provider/version;
4. repeated conformance tests and report upload verification.

Only claim the level for which evidence exists. GitHub Actions syntax
similarities do not guarantee that Gitea or Forgejo implements every action,
permission, expression, service, cache, or artifact behavior.

Woodpecker CI is an execution platform. Argo CD is a deployment controller and
belongs after CI; it does not replace scanner execution.
