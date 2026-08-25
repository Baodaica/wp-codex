# WordPress Bug Bounty Acceptance Gate

Accepted attacker levels:
- Unauthenticated
- Subscriber
- Contributor

Prioritize:

- Remote Code Execution
- Code Injection
- SQL Injection
- Stored XSS
- LFI
- RFI
- Directory Traversal
- Arbitrary File Read
- Arbitrary File Download
- Arbitrary File Upload
- Arbitrary File Deletion
- Sensitive Information Disclosure
- Arbitrary Options Update
- Authentication Bypass
- Privilege Escalation to Administrator

Reject early when clearly applicable:

- Reflected XSS
- CSRF-only
- Open Redirect
- Denial of Service
- Generic hardening
- Missing headers
- Dependency-only findings
- Administrator-only findings
- Arbitrary shortcode without accepted impact
- Non-admin privilege escalation without an accepted chained impact

Important:

Nonce verification is not authorization.
Authentication is not authorization.
is_admin() is not Administrator authorization.
