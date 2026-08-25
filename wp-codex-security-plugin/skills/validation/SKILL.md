---
name: validation
description: Use when Codex is already in the validation phase of a security scan or the user explicitly asks to determine whether one or more candidate security findings are valid. Do not use as the primary trigger for full PR, commit, branch, patch, or repository scans.
---

# WordPress Static Vulnerability Validation

Validate WordPress plugin security candidates using read-only
static source-code reasoning.

## Strict execution restrictions

Do NOT:

- execute PHP
- execute WordPress
- start a web server
- send HTTP requests
- invoke plugin callbacks
- modify target files
- exploit a running application
- install plugin dependencies into the target
- generate runtime confirmation claims without runtime evidence

The validator may read source code and existing scan artifacts.

## Validation questions

For every candidate determine:

1. What is the exact entrypoint?
2. What is the lowest attacker privilege?
3. Is the entrypoint actually reachable?
4. Which input is attacker controlled?
5. Is authentication required?
6. Is there a nonce?
7. Is there an authorization capability?
8. Is object ownership checked?
9. Is input restricted by a meaningful allowlist?
10. What transformations occur?
11. What exact argument reaches the sink?
12. Does WordPress core impose a relevant protection?
13. What concrete security impact remains?
14. What evidence argues against exploitability?
15. What proof gap remains?

## WordPress rules

Nonce verification alone is not authorization.

Authentication alone is not authorization.

is_admin() is not Administrator authorization.

current_user_can() must be evaluated using the exact capability.

REST permission_callback must be inspected.

SQL sanitization is not automatically SQL parameterization.

Filename sanitization is not automatically path containment.

File upload existence is not automatically executable file upload.

Option mutation is not automatically Administrator privilege
escalation; prove the security-sensitive option or chain.

## Dispositions

Use exactly one:

REPORTABLE

LIKELY_BUT_NEEDS_DYNAMIC_CONFIRMATION

SUPPRESSED

NOT_APPLICABLE

DEFERRED

REPORTABLE means the accepted vulnerability primitive and impact are
supported strongly by static evidence.

It does NOT mean a runtime exploit was executed.

LIKELY_BUT_NEEDS_DYNAMIC_CONFIRMATION means the source-code path is
strong but an important runtime condition still needs human testing.

SUPPRESSED means the path exists but fails the acceptance gate or is
adequately protected.

NOT_APPLICABLE means the candidate was produced by deterministic
mapping but does not represent the suspected vulnerability family.

DEFERRED means static evidence is insufficient and the candidate
should remain available for later analysis.

Always record counter-evidence and remaining uncertainty.
