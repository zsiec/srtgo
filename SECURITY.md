# Security Policy

## Scope

srtgo implements cryptographic functionality including:

- AES-128/192/256 encryption (CTR and GCM modes)
- PBKDF2 key derivation
- RFC 3394 AES key wrap
- SRT handshake and key exchange
- Key rotation

Security of these components is taken seriously.

## Reporting a Vulnerability

**Please do NOT open public GitHub issues for security vulnerabilities.**

Instead, report vulnerabilities through [GitHub Security Advisories](https://github.com/zsiec/srtgo/security/advisories/new).

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix target**: Within 30 days for confirmed vulnerabilities

## Supported Versions

Security fixes are applied to the latest release only.
