# Contributing

SecWeaver welcomes small, reviewable changes that keep the core portable and
the security claims evidence-based.

## Before a pull request

```sh
make validate
make test
./bin/secweaver --config secweaver.toml scan --dry-run
```

Keep changes focused. Update tests, schemas, documentation, and the support
matrix when behavior changes.

## Security-sensitive contributions

- Never include credentials, private hostnames, internal paths, proprietary
  rules, customer identifiers, or real vulnerable company code.
- Do not execute configuration through a shell or dynamic evaluator.
- Treat file paths, report content, repository names, branch names, and
  environment variables as attacker-controlled.
- Preserve distinct clean, findings, missing, error, timeout, skipped, and
  invalid-report states.
- Pin external actions and release images immutably in production examples.
- Record the license and provenance of new tools or rules.
- Add a negative test for the failure mode being fixed.

## Scanner adapters

An adapter must use an argument array, a timeout, a dedicated output file, and a
bounded parser. It must redact raw data before retention and document how the
tool signals findings versus execution failure. Arbitrary user-provided command
execution is out of scope.

## Language catalog

Popularity is not a single objective ranking. Changes to Tier 1 or Tier 2 must
update the dated ranking snapshot, coverage documentation, support matrix, and
tests in one pull request.

## License

By contributing, you agree that your contribution is available under the
project's 0BSD license. Identify any material not authored by you and do not
copy third-party rules into this repository unless their license is compatible
and retained.
