# Security Policy

## Supported versions

Only the latest release receives security fixes, so please update before reporting.

| Version        | Supported |
| -------------- | --------- |
| Latest 1.0.x   | Yes       |
| Anything older | No        |

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub:

1. Go to the [Security tab](https://github.com/rustwarden/RustWarden/security) of this repository.
2. Choose **Report a vulnerability** (or open <https://github.com/rustwarden/RustWarden/security/advisories/new>).
3. Describe the problem, the version you tested, steps to reproduce, and what an attacker could do with it.

Helpful extras: a proof of concept, whether administrator rights are needed, and whether Demo mode is affected.

### What to expect

- An acknowledgement within about 7 days.
- A fix or mitigation plan once the report is confirmed. This is a small project, so timing depends on severity and complexity.
- Credit in the release notes if you want it.

Please give us reasonable time to fix the issue before disclosing it publicly.

## Scope

In scope:

- Privilege escalation, or running code with the rights RustWarden holds when it runs as administrator.
- Firewall or QoS rules created by RustWarden that can be bypassed, tampered with, or left behind in a way that exposes the PC.
- Secrets (tokens, webhook URLs) stored or logged in plain text instead of with Windows DPAPI.
- Outbound network calls made without the user turning the feature on.
- Parsing flaws in downloaded data (block lists, country and ASN databases) or in network responses (scanner, Home Assistant, public IP lookup).
- Unsafe handling of files in `%LOCALAPPDATA%\RustWarden` or in the config file.

Out of scope:

- Problems that need an attacker who already has administrator rights on the PC.
- Findings in third-party services, block lists, or Windows itself.
- Denial of service by flooding your own network.
- Reports from automated scanners with no demonstrated impact.

## Design notes

- **Local first:** features that go online are off by default.
- **Secrets** are encrypted with Windows DPAPI.
- **Reversible rules:** every firewall rule or QoS policy RustWarden creates is tagged as its own and can be removed in bulk ("Restore firewall defaults").
- **No driver:** RustWarden runs entirely in user mode.
