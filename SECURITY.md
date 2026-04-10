# Security Policy

This security policy applies to the security-sensitive crates in the `rust-tidecoin` workspace.
The most important ones are:

- `tidecoin`
- `consensus-core`
- `consensus`
- `primitives`
- `hashes`
- `internals`
- `base58`
- `io`
- `units`

These crates deal with consensus rules, serialization, address/script handling, and
cryptographic algorithms, so they are the most likely locations for security-sensitive defects.

As a general rule, an issue is a security vulnerability if it could lead to:

- loss of funds
- loss of privacy
- censorship, including by attaching an incorrectly low fee to a transaction
- remote code execution, invalid memory access, or another ordinary security failure

If you are not sure whether an issue is security-sensitive, treat it as private first.

**If you believe you are aware of a security issue**, contact the Tidecoin maintainers privately
through the repository's security advisory channel. Do not post consensus, serialization,
cryptographic, or remote-crash vulnerabilities to the public issue tracker before maintainers have
had a chance to triage them.
