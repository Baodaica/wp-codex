---
name: security-scan
description: "Use for a standard, single-pass security audit of an entire repository or a scoped path, package, folder, or submodule with no diff to review. This is the default repository scan. Do not use for PR, commit, branch, or working-tree diffs, or for deep, multi-pass scans."
---

# WordPress Plugin Security Scan

This security-scan workflow is specialized for authorized,
read-only static security review of WordPress plugins.

Do NOT perform generic repository-wide security discovery.

Do NOT review every repository file simply to achieve generic coverage.

The primary scan strategy is:

WordPress static mapper
-> candidate generation
-> candidate prioritization
-> targeted source-to-control-to-sink reasoning
-> static validation
-> final findings

## Scope

The scan target MUST be a WordPress plugin directory.

Prioritize these attacker levels:

1. Unauthenticated
2. Subscriber
3. Contributor

Always determine the lowest privilege required.

Read and apply:

- references/wordpress/threat-model.md
- references/wordpress/semantics.md
- references/wordpress/acceptance-gate.md

## Safety

This workflow is static and read-only.

Do NOT:

- modify target plugin files
- execute PHP plugin code
- invoke WordPress callbacks
- send HTTP requests
- start WordPress
- exploit a running target
- install target plugin dependencies
- write into the target plugin directory

Local static-analysis scripts may read source files and write scan
artifacts outside the target plugin directory.

## Phase 1 — WordPress deterministic mapping

Before using expensive model reasoning for vulnerability discovery,
run the local WordPress mappers against the scan target.

Run:

<python_command> <plugin_dir>/scripts/wordpress/wp_surface_map.py <TARGET>

Then run:

<python_command> <plugin_dir>/scripts/wordpress/wp_candidate_map.py <TARGET>

The candidate mapper produces:

/opt/codex-security/wpsec-output/<PLUGIN>/v2/summary.json

/opt/codex-security/wpsec-output/<PLUGIN>/v2/candidates.json

/opt/codex-security/wpsec-output/<PLUGIN>/v2/unresolved-entrypoints.json

## Phase 2 — Candidate-first review

Read summary.json first.

Then read candidates.json.

Do NOT begin by reading every PHP file in the target.

The deterministic mapper has already inventoried generic
WordPress entrypoints, security controls, sources, and dangerous sinks.

Use the candidate ledger as the primary discovery queue.

Review candidates in descending score order.

Prioritize:

- unauthenticated paths
- authenticated paths without capability authorization
- REST routes whose permission_callback requires analysis
- user-controlled sources
- option mutation
- user/role mutation
- SQL sinks
- file operations
- include/require
- command execution
- unsafe deserialization

## Phase 3 — Targeted code reading

For each candidate, initially read ONLY:

1. entrypoint registration
2. resolved callback
3. candidate code slice
4. nearby authorization checks
5. nearby input handling
6. nearby sink arguments

Do not open unrelated source files.

Follow another function or method ONLY when necessary to answer one
of these questions:

- Is the attacker-controlled value transformed here?
- Is authorization enforced here?
- Is object ownership enforced here?
- Is the value restricted by an allowlist?
- Does the dangerous sink occur in this helper?
- Does this helper change the candidate's concrete impact?
- Does WordPress core provide a relevant protection?

When following helpers, prefer the smallest relevant source slice.

## Phase 4 — WordPress semantics

Apply these rules strictly.

wp_ajax_nopriv_* means unauthenticated reachability.

wp_ajax_* means authentication only.
It does NOT prove authorization.

admin_post_nopriv_* means unauthenticated reachability.

admin_post_* means authentication only.
It does NOT prove authorization.

check_ajax_referer(), wp_verify_nonce(), and
check_admin_referer() are NOT authorization controls.

A nonce is primarily a CSRF/intention mechanism.

is_admin() does NOT mean the current user is an Administrator.

Authorization claims must be supported by capability,
ownership, or equivalent enforcement.

For REST routes, inspect the actual permission_callback.

__return_true means the REST permission check permits public access.

For current_user_can() and user_can(), inspect the exact capability.

## Phase 5 — Source to control to sink

For every surviving candidate establish:

ENTRYPOINT
-> ATTACKER ROLE
-> ATTACKER-CONTROLLED SOURCE
-> TRANSFORMATIONS
-> AUTHENTICATION
-> NONCE
-> CAPABILITY / OWNERSHIP
-> SINK
-> CONCRETE IMPACT

Do not infer vulnerability merely because a dangerous sink exists.

Do not infer safety merely because a nonce exists.

Do not infer SQL safety merely because sanitization exists.

Do not infer filesystem safety merely because a filename was sanitized.

## Phase 6 — Acceptance gate

Only spend significant validation budget on these impact families:

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

Suppress clearly out-of-scope findings early:

- Reflected XSS
- CSRF-only
- Open Redirect
- Denial of Service
- generic hardening
- missing security headers
- dependency-only findings
- Administrator-only vulnerabilities
- arbitrary shortcode without accepted impact
- non-admin privilege escalation without an accepted chained impact

Do not spend additional reasoning cycles validating a finding that
clearly fails this gate.

## Phase 7 — Candidate disposition

Each candidate must receive one disposition:

REPORTABLE

LIKELY_BUT_NEEDS_DYNAMIC_CONFIRMATION

SUPPRESSED

NOT_APPLICABLE

DEFERRED

For each candidate record:

- candidate ID
- vulnerability family
- entrypoint
- minimum attacker role
- source
- authorization control
- nonce control
- ownership control
- transformation / sanitization
- sink
- concrete impact
- counter-evidence
- remaining proof gap
- disposition
- confidence

## Phase 8 — Direct primitive vs chain

If a direct source-to-sink path already proves an accepted impact,
do NOT launch a separate expensive attack-path phase merely to
restate the same path.

Use deeper attack-path reasoning only when exploitation requires a
meaningful multi-step chain.

Examples:

arbitrary option update
-> security-sensitive option
-> Administrator takeover

or:

file upload
-> extension/path bypass
-> executable web-accessible file
-> RCE

or:

user mutation
-> role/capability mutation
-> Administrator privilege

## Phase 9 — Coverage

Coverage is measured against WordPress security-relevant surfaces,
NOT against blindly reading every file.

Report:

- PHP files mapped
- entrypoints mapped
- callbacks resolved
- unresolved callbacks
- raw sensitive sinks
- candidates generated
- candidates validated
- candidates suppressed
- candidates deferred

Explicitly state unresolved callbacks or paths as coverage gaps.

Do not claim complete security coverage when unresolved paths remain.

## Phase 10 — Final output

Final findings must be concise.

For each reportable finding provide:

- title
- affected file/function
- attacker role
- entrypoint
- source
- missing/broken security control
- sink
- concrete impact
- static evidence
- remaining dynamic proof requirement, if any

Never label runtime exploitability as dynamically confirmed unless
a separate authorized dynamic test actually occurred.
