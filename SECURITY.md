# Security Policy

MachOInspector parses untrusted input. Bugs that let crafted input crash the process, hang it, exhaust memory, read out of bounds, or (for extraction) write outside the destination are security issues.

## Supported versions

Only the latest release receives fixes while the project is at 0.x.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub:
**Security → Report a vulnerability** on https://github.com/d-date/swift-macho-inspector (private vulnerability reporting).

Include a minimal reproducing input (base64 or a generator script is fine), the observed behaviour, and the platform and Swift version.

You can expect an acknowledgement within 7 days. Once a fix is released, an advisory will be published with credit, unless you prefer to stay anonymous.
