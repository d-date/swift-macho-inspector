# Contributing to MachOInspector

Thanks for your interest! Bug reports, test cases and pull requests are welcome.

## Development

```sh
swift build
swift test
swift format lint --strict -r Sources Tests Package.swift
```

CI runs on Linux (Swift 6.3 and 6.4 containers). To reproduce it locally:

```sh
docker run --rm -v "$PWD":/src -w /src swift:6.4-noble swift test --scratch-path /tmp/build
```

## Guidelines

- Keep the package dependency-light and Foundation-only, so it builds on Linux and macOS.
- Treat all input as hostile. Every read must be bounds-checked, with no traps (force unwraps, overflowing arithmetic) on input-derived values and no unbounded allocations or loops. New limits must be documented.
- Every behaviour change needs a test. Parser fixes should include the malformed input that triggered them.
- Format with `swift format format -i -r Sources Tests Package.swift`.
- Public API changes before 1.0 are allowed, but call them out in the pull request description.
- For security issues, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

By contributing, you agree that your contributions are licensed under the MIT License.
