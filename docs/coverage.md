# Language coverage

<!-- markdownlint-disable MD013 -->

SecWeaver maintains a 50-entry language catalog. Tier 1 contains 20 priority
languages and Tier 2 broadens the catalog by another 30.

**“20/20 coverage” means integration coverage for all 20 Tier 1 catalog
entries. It never means 100% vulnerability detection, perfect parsing, complete
framework coverage, or support for every package manager.**

## What integration coverage means

For a cataloged source language, SecWeaver can:

1. identify matching files using maintained extensions or filenames;
2. run language-independent Gitleaks and Trivy filesystem checks;
3. invoke Opengrep with the configured local rules;
4. run OSV-Scanner over the repository, allowing OSV-Scanner to recognize the
   dependency formats it supports;
5. report detected file counts and normalized findings.

Those operations are useful across mixed-language repositories, but their
depth differs by language:

- Gitleaks searches content and Git history; it is not language-semantic.
- Trivy coverage depends on target type, package metadata, and vulnerability
  database support.
- Opengrep needs both a parser and relevant rules. A parser alone is not a
  security ruleset.
- OSV-Scanner needs supported manifests, lockfiles, packages, and database
  records.
- Generic rules can find cross-language patterns but cannot replace
  language-aware data-flow analysis.

If a language has no applicable dependency ecosystem, dependency scanning is
`not applicable`, not silently “complete.”

## Tier 1: 20 integration profiles

The built-in catalog currently defines these 20 entries:

| Language | Catalog SAST maturity | Dependency metadata declared in catalog | Recommended optional analyzer |
| --- | --- | --- | --- |
| TypeScript | Community | npm | ESLint security rules |
| Python | Community | PyPI | Bandit |
| JavaScript | Community | npm | ESLint security rules |
| Java | Community | Maven | SpotBugs with FindSecBugs |
| C# | Community | NuGet | Roslyn analyzers |
| PHP | Community | Packagist | Psalm or PHPStan security rules |
| Shell | Experimental | None | ShellCheck |
| C++ | Community | Conan | Clang Static Analyzer, clang-tidy, or cppcheck |
| HCL/Terraform | Community | Terraform | TFLint and `terraform validate` |
| Go | Community | Go | gosec and govulncheck |
| C | Community | Conan | Clang Static Analyzer, clang-tidy, or cppcheck |
| SQL | Generic | None | SQLFluff plus reviewed database-specific rules |
| Rust | Community | crates.io | Clippy, cargo-audit, and cargo-deny |
| Kotlin | Community | Maven | Detekt and JVM bytecode analysis where applicable |
| Ruby | Community | RubyGems | Brakeman and bundler-audit |
| Swift | Community | SwiftURL | SwiftLint and native build checks |
| Dart | Experimental | Pub | `dart analyze` |
| R | Experimental | CRAN | lintr |
| Scala | Community | Maven | Scalafix/Scalastyle and JVM bytecode analysis |
| Lua | Experimental | LuaRocks | luacheck |

“Community,” “experimental,” and “generic” are catalog declarations about the
intended Opengrep integration level. They are not a guarantee that the bundled
baseline has a dedicated rule for every framework or vulnerability category.
The shipped 0BSD baseline is deliberately small and uses auditable generic
rules.

Optional analyzers in the last column are architectural recommendations. They
are not invoked by the current Python core and must not be shown as completed
scanner stages unless a CI workflow actually installs, runs, parses, and tests
them.

## Tier 2: broader baseline

Tier 2 currently includes:

- Objective-C
- PowerShell
- Perl
- Groovy
- Elixir
- Clojure
- Haskell
- Julia
- MATLAB
- COBOL
- Fortran
- Assembly
- Solidity
- Apex
- Visual Basic .NET
- F#
- OCaml
- Erlang
- Common Lisp
- Scheme
- Prolog
- Ada
- Zig
- Nim
- Crystal
- Tcl
- Delphi/Object Pascal
- SAS
- ABAP
- VHDL

Some Tier 2 entries have an Opengrep parser or can reuse an ecosystem scanner.
Others receive only the universal repository baseline unless an optional native
analyzer is configured. Languages such as Assembly, COBOL, Fortran, SAS, ABAP,
and VHDL must not be presented as having the same semantic security depth as
Java, Python, or JavaScript.

## Catalog, not universal ranking

The catalog is a maintained project priority list, not an assertion that one
objective worldwide ranking exists. GitHub activity, developer surveys,
search-based indexes, package downloads, and job postings use different
methodologies and produce different orders.

When a README calls the list “top 20” or “top 50,” it should also state:

- the source or combination of sources;
- the snapshot date;
- whether markup, query, hardware-description, and scripting languages are
  included;
- that ranking changes do not automatically prove scanner support.

Rank updates should use a reviewed pull request and should not silently change
coverage claims.

## Evidence levels

Use these terms consistently:

| Status | Required evidence |
| --- | --- |
| Cataloged | Entry loads, detection rules are valid, and no duplicate name exists |
| Config validated | `secweaver validate` accepts the intended configuration |
| Fixture tested | A safe positive fixture produces the expected scanner finding and a clean fixture avoids that finding |
| Platform tested | The fixture test completed on the named runner OS and version |
| Provider tested | A real workflow completed on the named CI product and version |
| Verified | All evidence required by the specific claim is recorded and current |

A checked-in workflow file is not evidence of a successful provider run.
Likewise, local success on Linux is not evidence for Windows Server, macOS, or
FreeBSD.

## Recommended fixture strategy

For each Tier 1 language:

- include a minimal detection fixture;
- include a non-secret placeholder that cannot authenticate anywhere;
- add a harmless insecure-code pattern expected by a reviewed rule;
- add a clean counterpart;
- include a supported dependency lockfile only when redistribution is safe;
- assert scanner status and normalized rule ID;
- test report redaction;
- record scanner and database versions used by the test.

Never place an active key, realistic company endpoint, private package name, or
internal source sample in a public fixture.

## Mixed-language and generated code limitations

File detection is extension- and filename-based. Ambiguous extensions are
assigned according to catalog order, and one file is counted once. For example,
`.m` can represent Objective-C or MATLAB; catalog order affects the result.

Generated, vendored, and copied sources can inflate language counts and findings.
The default exclusions cover common directories, but repositories should add
their own generated and vendor paths. Exclusions reduce noise and runtime; they
can also hide risk, so changes require review.

## Safe public wording

Recommended:

> SecWeaver provides integration profiles for 20/20 priority catalog languages
> and baseline repository coverage for 50 catalog entries. Scanner depth varies
> by parser, ruleset, package metadata, artifact, and vulnerability database.

Avoid:

> SecWeaver detects 100% of vulnerabilities in the world's top 20 or top 50
> languages.
