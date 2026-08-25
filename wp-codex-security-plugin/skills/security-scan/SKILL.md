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

<python_command> <plugin_dir>/scripts/wordpress/wp_candidate_map_v5.py <TARGET>

The candidate mapper produces:

/opt/codex-security/wpsec-output/<PLUGIN>/v2/summary.json

/opt/codex-security/wpsec-output/<PLUGIN>/v2/review-index.json

Full drill-down artifacts are also produced locally:

/opt/codex-security/wpsec-output/<PLUGIN>/v2/candidates.json

/opt/codex-security/wpsec-output/<PLUGIN>/v2/review-units.json

/opt/codex-security/wpsec-output/<PLUGIN>/v2/unresolved-entrypoints.json

## Phase 2 — Candidate-first review

Read summary.json first.

Then read review-index.json.

Do NOT load candidates.json, review-units.json, callbacks.json,
surface-map.json, or other full graph artifacts into the initial
model context.

Those full artifacts are local drill-down data only.

Do NOT begin by reading every PHP file in the target.

The deterministic mapper has already inventoried WordPress
entrypoints, reachable callbacks, sources, controls, dangerous
sinks, and clustered review units.

Use review-index.json as the primary discovery queue.

Review units in descending priority/score order.

For a selected review unit, open only the exact entrypoint,
callback, sink locations, and helper functions required to
validate that unit.

Do not load the full candidate graph merely because it exists.

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


## WordPress Candidate-First Orchestration Override

When the authorized target is a WordPress plugin and
`wpsec-output/<PLUGIN>/v2/review-index.json` exists, this workflow
takes precedence over generic repository-wide discovery behavior.

### Coverage semantics

Complete WordPress security coverage means reviewing all review units
produced by the deterministic WordPress mapper plus unresolved
entrypoints that require manual resolution.

It does NOT require reading every PHP file in the plugin.

Files with no mapped entrypoint, reachable helper path, sensitive sink,
security control, or unresolved registration do not require semantic
model review merely to satisfy repository file coverage.

### Primary queue

Use:

`wpsec-output/<PLUGIN>/v2/review-index.json`

as the complete initial semantic review queue.

Review every unit in the index unless the user explicitly requests
partial coverage.

Do NOT initially load:

- candidates.json
- review-units.json
- callbacks.json
- surface-map.json

These are drill-down artifacts only.

### Per-unit source boundary

For each review unit, initially inspect only:

1. the entrypoint registration;
2. the resolved callback;
3. the listed sink locations;
4. listed security-control locations;
5. helper functions on the mapped call path required to determine
   attacker-to-sink reachability.

Expand beyond those locations only when a concrete unresolved dataflow,
dispatch target, authorization check, sanitization step, dynamic
callback, inheritance relationship, or security-sensitive helper
requires it.

Do not perform repository-wide grep/find discovery for a review unit
when the mapper has already supplied the relevant source anchors.

### Subagents

Do not launch a generic repository-wide baseline auditor for WordPress
candidate-first scans.

If subagents are available, assign them bounded groups of review units.

Each WordPress investigator MUST treat its assigned review units as the
primary investigation boundary.

It may follow concrete source-backed helper edges outside those units
when necessary to validate the assigned attack path, but MUST NOT
perform an independent full-repository audit or attempt to satisfy
per-file repository coverage.

Do not duplicate the same review unit across workers unless parent
validation of a potential reportable finding specifically requires an
independent second review.

### Full-artifact escalation

Load an individual matching object from review-units.json or
candidates.json only when review-index.json lacks evidence required to
resolve a specific unit.

Never load either full artifact merely for discovery or completeness.

### WordPress completeness

Before finishing, verify:

- every review-index unit has a disposition;
- every unresolved entrypoint has been resolved, excluded with evidence,
  or explicitly reported unresolved;
- every reportable finding has source-backed attacker-to-impact
  reachability;
- no unit was silently dropped because its initial heuristic score was
  low.

Do not equate PHP-file enumeration with WordPress security coverage.


## WordPress Security Graph V5 Orchestration

When the target is a WordPress plugin and the V5 artifacts exist:

`wpsec-output/<PLUGIN>/v5/summary.json`

`wpsec-output/<PLUGIN>/v5/review-index.json`

`wpsec-output/<PLUGIN>/v5/gap-index.json`

the V5 workflow takes precedence over the V4 candidate-first workflow.

### Initial context

Initially read only:

1. `v5/summary.json`
2. `v5/review-index.json`
3. `v5/gap-index.json`

Do NOT initially load:

- `v5/security-graph.json`
- `v2/candidates.json`
- `v2/review-units.json`
- `v2/review-index.json`
- `callbacks.json`
- `surface-map.json`

The full V5 security graph and V4 artifacts are drill-down or fallback
evidence only.

### V5 security coverage

The deterministic V5 frontend inventories WordPress registrations,
request-relevant callbacks, bounded call paths, request sources,
security controls, security effects, flow confidence, and unresolved
security-relevant gaps.

Security coverage is based on disposition of:

- every V5 review unit; and
- every V5 model-facing gap unit.

Do not equate security coverage with reading every PHP file.

Do not launch a generic repository-wide baseline audit merely to achieve
file coverage.

### Review effort

`review_effort` is model-work prioritization only. It is NOT severity
and MUST NOT be used to suppress a unit.

For `deep` units:

- perform complete semantic validation;
- verify attacker reachability;
- verify source-to-effect flow;
- inspect applicable authorization and sink-specific controls;
- actively seek counter-evidence;
- derive concrete impact;
- consider viable attack chaining.

For `normal` units:

- perform standard semantic validation;
- inspect the provided source anchors first;
- deepen the review only when a plausible security invariant violation
  remains.

For `bounded` or flow-`unknown` units:

- perform a bounded semantic check of the registration, callback,
  relevant locations, and necessary helper edges;
- never interpret `unknown` as safe;
- escalate the unit to normal or deep review if a plausible attack path
  appears.

### Per-unit source boundary

Start from the source locations listed in `review-index.json`.

Inspect only the registration, callback, relevant locations, and helper
definitions necessary to validate the specific unit.

Follow concrete call, dataflow, inheritance, ownership, authorization,
or framework-semantic edges when necessary.

Do not perform repository-wide grep/find discovery for a review unit
when deterministic V5 source anchors already identify its security
surface.

### Gap units

Each item in `gap-index.json` is a bounded unresolved security-analysis
task.

Resolve only the stated gap and the minimal local dependencies required
for that resolution.

Examples include:

- dynamic hook resolution;
- dynamic callback resolution;
- dynamic dispatch;
- unresolved dataflow;
- inheritance ambiguity;
- framework semantic ambiguity.

A gap resolver may follow bounded backward or forward source edges, but
MUST NOT restart a full repository audit.

If the gap becomes resolvable:

- convert it conceptually into a normal review path;
- validate its security semantics.

If the gap cannot be resolved statically:

- record it as deferred or unresolved with the exact proof gap;
- do not silently treat it as safe.

### Security graph drill-down

`v5/security-graph.json` is a local drill-down artifact.

Do not load it wholesale.

When additional deterministic evidence is needed for one review unit,
retrieve only the matching unit/path information or inspect the exact
source anchors directly.

### V4 fallback

V4 artifacts may be consulted only when:

1. V5 artifacts are absent; or
2. a concrete V5 review/gap unit exposes a coverage discrepancy that
   requires comparison with the legacy mapper.

Do not run the V4 queue in parallel with a complete V5 queue merely for
completeness.

### Novel vulnerability reasoning

V5 taxonomy is a discovery aid, not an exhaustive vulnerability list.

For each security-relevant V5 path, reason about the violated security
invariant rather than requiring the path to match a predefined
vulnerability family.

Consider, where source evidence supports it:

- authentication bypass;
- authorization bypass;
- object-level authorization failure;
- privilege escalation;
- sensitive information disclosure;
- unsafe state transition;
- injection;
- arbitrary filesystem effects;
- unsafe code execution;
- cross-boundary request effects;
- chained impact.

Do NOT run an independent repository-wide novelty scan.

Novel findings must originate from the supplied V5 security graph,
review units, bounded gap resolution, or a concrete helper path reached
from them.

### Preserve Codex Security strengths

V5 changes discovery and work scheduling only.

Preserve the original Codex Security strengths during semantic review:

- threat-boundary reasoning;
- attacker capability analysis;
- source-backed attack-path reasoning;
- active counter-evidence search;
- WordPress authorization semantics;
- business-logic reasoning;
- attack-chain reasoning;
- independent validation for plausible reportable findings;
- calibrated severity and confidence;
- honest unresolved/deferred work;
- canonical findings and reporting.

Do not reduce semantic validation quality merely because deterministic
discovery reduced the amount of source that requires model review.

### Completion

A V5 WordPress scan may be marked complete only when:

- every review unit has a disposition;
- every model-facing gap has a resolution or explicit unresolved/deferred
  disposition;
- every reportable finding has source-backed attacker-to-impact
  reachability;
- applicable counter-evidence was checked;
- no unit was silently discarded because of low priority or unknown flow.

