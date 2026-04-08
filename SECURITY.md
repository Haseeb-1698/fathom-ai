# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of Fathom seriously. If you have discovered a security vulnerability, we appreciate your help in disclosing it to us in a responsible manner.

### Please DO:

* Report vulnerabilities to us directly before disclosing them publicly
* Provide enough information to reproduce the vulnerability
* Give us reasonable time to fix the issue before public disclosure

### Please DO NOT:

* Access, modify, or delete data that isn't yours
* Perform actions that could affect other users
* Use automated tools to find vulnerabilities at scale

### How to Report

**Email:** security@example.com (replace with actual security email)

Please include:

1. **Description** of the vulnerability
2. **Steps to reproduce** the issue
3. **Potential impact** of the vulnerability
4. **Your contact information** for follow-up

### What to Expect

1. **Acknowledgment** within 48 hours
2. **Initial assessment** within 5 business days
3. **Regular updates** on remediation progress
4. **Credit** in our security acknowledgments (if desired)

### Scope

**In Scope:**
- Fathom backend API
- Fathom dashboard frontend
- Model inference server
- Docker configurations

**Out of Scope:**
- Third-party dependencies (report to maintainers directly)
- Social engineering attacks
- Physical security
- DoS attacks

## Security Best Practices

When deploying Fathom:

1. **Never commit secrets** — Use environment variables or secret managers
2. **Enable authentication** — Configure Firebase or your preferred auth provider
3. **Use HTTPS** — Configure SSL/TLS in production
4. **Restrict API access** — Use API tokens and rate limiting
5. **Keep dependencies updated** — Regularly update Python and Node packages
6. **Secure Neo4j** — Change default credentials and restrict network access
7. **Monitor logs** — Set up alerting for suspicious activity

## Security Features

Fathom includes several built-in security measures:

- **Input sanitization** — All user inputs are validated and sanitized
- **Output validation** — Model outputs are checked for injection attempts
- **Rate limiting** — API endpoints are rate-limited to prevent abuse
- **Bearer token auth** — Optional API authentication
- **CORS configuration** — Configurable allowed origins
- **Audit logging** — Request logging for security analysis

## Disclosure Policy

We follow responsible disclosure:

1. We will acknowledge your report within 48 hours
2. We will confirm the vulnerability and determine its severity
3. We will develop and test a fix
4. We will release the fix and publish an advisory
5. We will credit you (if desired) in the advisory

Thank you for helping keep Fathom and our users safe!
