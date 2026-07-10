# Security Policy

## Supported Versions

TaintGate is currently in pre-1.0 development. We actively support security
updates for the latest `0.x` release line only:

| Version | Supported          |
| ------- | ------------------ |
| 0.x     | :white_check_mark: |

## Reporting a Vulnerability

We take the security of TaintGate seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Reporting Process

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of the following methods:

1. **GitHub Security Advisories (Preferred)**: Report privately through the
   [GitHub Security Advisory form](https://github.com/kiranv926/taintgate/security/advisories/new).
   This keeps the report private and lets us collaborate on a fix directly.

2. **Email**: `security@taintgate.dev`
   - Use the subject line: `[SECURITY] Brief description of the issue`

### What to Include

Please include the following information in your report:

- **Type of issue** (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- **Full paths of source file(s) related to the manifestation of the issue**
- **Location of the affected source code** (tag/branch/commit or direct URL)
- **Step-by-step instructions to reproduce the issue**
- **Proof-of-concept or exploit code** (if possible)
- **Impact of the issue**, including how an attacker might exploit the issue
- **Your suggested fix** (if you have one)

### Response SLA

We are committed to responding to security reports in a timely manner:

- **Initial Response**: Within 48 hours of report receipt
- **Status Update**: Within 7 days with an assessment and next steps
- **Resolution Timeline**: 
  - Critical vulnerabilities: Patch within 30 days
  - High severity: Patch within 90 days
  - Medium/Low severity: Addressed in next release cycle

### Disclosure Policy

We follow a **coordinated disclosure** process:

1. **Private Disclosure**: Security issues are kept private until a fix is available
2. **Credit**: With your permission, we will credit you in the security advisory
3. **Public Disclosure**: After a patch is released, we will publish a security advisory
4. **CVE Assignment**: Critical and high-severity issues will receive CVE assignments

### What We Promise

- We will respond to your report promptly
- We will keep you informed of the progress toward resolving the issue
- We will credit you for the discovery (unless you prefer to remain anonymous)
- We will not take legal action against security researchers acting in good faith

### Out of Scope

The following are **not** considered security vulnerabilities:

- Issues that require physical access to the device
- Issues that require social engineering
- Denial of service (DoS) attacks that don't compromise data integrity
- Issues in third-party dependencies (please report to the upstream project)
- Issues that require already-compromised user credentials
- Self-XSS (cross-site scripting that requires user interaction with malicious payload)

### Security Best Practices

If you're using TaintGate in production:

1. **Keep dependencies updated**: Regularly update to the latest stable version
2. **Review security advisories**: Subscribe to GitHub security alerts
3. **Use fail-closed mode**: Enable fail-closed behavior for maximum security
4. **Audit logging**: Enable comprehensive audit logging for compliance
5. **Network security**: Deploy behind firewalls and use TLS for all connections
6. **Access control**: Implement proper authentication and authorization
7. **Regular security audits**: Conduct periodic security reviews

### Security Updates

Security updates are released as:
- **Patch releases** (e.g., 0.2.1) for critical security fixes
- **Minor releases** (e.g., 0.3.0) for security enhancements
- **Security advisories** published on GitHub

### Contact

For general security questions or concerns:
- **Email**: `security@taintgate.dev`
- **GitHub Discussions**: [Security Discussions](https://github.com/kiranv926/taintgate/discussions/categories/security)

---

**Thank you for helping keep TaintGate and its users safe!**

