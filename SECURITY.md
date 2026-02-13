# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in zvec, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please send a detailed report to the maintainers via one of the following:

1. **GitHub Security Advisories**: Use the [private vulnerability reporting](https://github.com/alibaba/zvec/security/advisories/new) feature on GitHub.
2. **Email**: Contact the maintainers directly (see the project's GitHub organization page for contact details).

### What to include

- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Affected versions
- Any suggested fix (optional)

### Response timeline

- **Acknowledgment**: Within 3 business days
- **Initial assessment**: Within 7 business days
- **Fix timeline**: Depends on severity; critical issues will be prioritized

### Severity levels

- **Critical**: Remote code execution, data corruption, authentication bypass
- **High**: Denial of service, memory corruption, information disclosure
- **Medium**: Local privilege escalation, unsafe defaults
- **Low**: Minor issues with limited exploitability

## Security best practices for users

- Keep zvec updated to the latest version
- Do not expose zvec's data directory to untrusted users
- Validate and sanitize all query inputs from untrusted sources
- Use appropriate file system permissions on database directories
- When using API extensions (OpenAI, Qwen), store API keys in environment variables, never in code
