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



## WordPress Security State Graph V6

When these artifacts exist:

`wpsec-output/<PLUGIN>/v6/summary.json`

`wpsec-output/<PLUGIN>/v6/review-index.json`

the V6 state-transition queue supplements the V5 security graph.

V6 does not replace V5.

Use both:

- V5 for request/dataflow/effect-oriented security paths;
- V6 for authorization, identity, ownership, authentication,
  privilege, configuration, token, and security-state transitions.

### Initial V6 context

Read:

1. `v6/summary.json`
2. `v6/review-index.json`

Do NOT initially load the complete:

`v6/security-state-graph.json`

The full state graph is drill-down evidence only.

### V6 review purpose

V6 units identify security-sensitive state transitions that may not
contain a traditional injection, file, SQL, or code-execution sink.

For each V6 unit determine:

- minimum attacker privilege;
- whether the operation is remotely/request reachable;
- whether the attacker controls the target user/object identity;
- whether ownership is enforced;
- whether a capability check protects the transition;
- whether nonce/token checks are being mistaken for authorization;
- what security meaning the changed state has;
- which downstream code consumes the changed state;
- whether the transition enables a second privileged workflow.

### Privilege escalation reasoning

For role, capability, user-state, or configuration transitions, explicitly
consider chains such as:

unauthenticated -> account creation -> privileged role

subscriber -> user/config mutation -> administrator capability

low-privilege user -> security option change -> privileged registration

user-meta mutation -> approval/verification bypass -> privileged access

configuration mutation -> newly reachable privileged surface

Do not require a direct `set_role()` call in the original request handler
if a changed configuration or state value causes privilege assignment
downstream.

### Account takeover reasoning

For password, email, identity, token, or authentication transitions,
explicitly verify:

- victim selection;
- ownership proof;
- password-reset token generation and validation;
- token binding to victim identity;
- token replay;
- token disclosure;
- ability to change another user's password or email;
- session/authentication establishment after the transition.

Consider multi-request workflows.

Do not restrict account-takeover analysis to a single callback when the
security transition is completed across multiple requests.

### Nonce semantics

A valid WordPress nonce is a CSRF control and is not, by itself,
authorization.

Do not suppress a V6 unit merely because `wp_verify_nonce`,
`check_ajax_referer`, or `check_admin_referer` is present.

Capability, ownership, target-object authority, and workflow semantics must
still be evaluated.

### Configuration semantics

For security-relevant configuration writes:

1. identify the option/key being modified;
2. determine whether the attacker controls the value;
3. locate security-sensitive consumers of the option;
4. determine whether the changed value modifies:
   - registration;
   - authentication;
   - authorization;
   - role assignment;
   - capability assignment;
   - verification;
   - approval;
   - privileged routing;
   - access-control behavior.

Follow concrete downstream consumers rather than declaring every
`update_option()` call vulnerable.

### Security-state completeness

A WordPress scan must not be considered semantically complete solely because
V5 sink/dataflow review is complete.

When V6 artifacts exist:

- every V6 review unit must receive a disposition;
- unresolved ownership or authorization questions must remain explicit;
- possible privilege/account-takeover chains must be followed to a concrete
  security impact or rejected with source-backed counter-evidence.

### Bounded investigation

V6 is intended to avoid generic repository-wide rediscovery.

Start from the V6 function/state-transition unit and inspect only:

- its registration/exposure;
- target identity/object derivation;
- authorization controls;
- state mutation;
- direct downstream security consumers;
- concrete helper paths required to validate the chain.

Expand further only when a source-backed transition requires it.

### Preserve semantic reasoning

V6 state units are discovery hints, not vulnerability findings.

Codex remains responsible for:

- business-logic reasoning;
- authorization semantics;
- ownership semantics;
- multi-step attack chains;
- counter-evidence;
- final exploitability;
- severity;
- confidence.


## WordPress V6.1 Coverage Safety Net

Candidate and state-unit mapping are prioritization mechanisms, not
security coverage boundaries.

When `wpsec-output/<PLUGIN>/v6.1/` exists, use the V6.1 artifacts after
the primary V5 and V6 queues.

### Orphan security queue

Review every item in:

`v6.1/orphan-review-index.json`

unless deterministic evidence proves that the unit is already represented
by a primary review unit.

An orphan unit means security-sensitive or security-like custom code was
identified but was not confidently connected to the primary V5/V6 queue.

Do not treat an orphan unit as a vulnerability.

For each orphan unit:

1. resolve bounded reverse callers;
2. determine request reachability;
3. determine attacker privilege;
4. determine attacker-controlled parameters;
5. determine target identity or object;
6. determine the actual state semantics;
7. follow concrete downstream security consumers when necessary.

Do not perform a repository-wide semantic audit merely because an orphan
exists.

### Reverse security reachability

Security-sensitive custom functions may be discovered before their public
entrypoint is known.

Use the bounded reverse-call evidence to work from:

security-sensitive operation
<- helper
<- caller
<- request entrypoint

Expand only along concrete source-backed caller relationships required to
resolve the security path.

### Cross-request state dependencies

Review every plausible item in:

`v6.1/cross-state-index.json`

as a state-dependency hypothesis.

Determine whether a producer and consumer actually share the same:

- option;
- meta key;
- custom database field;
- account state;
- role or capability state;
- approval or verification state;
- authentication state;
- plugin-specific security state.

Explicitly consider:

request A
-> attacker-controlled state mutation
-> persisted state
-> request B
-> security-sensitive consumer
-> privilege/authentication/authorization consequence

A shared semantic hint is not sufficient proof. Validate the concrete
state key or object before reporting.

### Custom security abstractions

Do not require WordPress core primitives to recognize a possible security
boundary.

Custom abstractions such as:

- grant_access
- set_level
- approve_member
- verify_account
- activate_user
- change_owner
- promote_member
- update_membership

may implement security-sensitive state using custom tables, custom objects,
or wrapper functions.

Naming is only a discovery signal.

Codex must determine actual semantics from source before accepting or
rejecting the path.

### Completeness rule

A WordPress scan must not be marked complete solely because all V5
candidates or V6 state units were reviewed.

When V6.1 artifacts exist, completion additionally requires:

- every orphan review unit has a disposition;
- every material cross-state hypothesis has a disposition;
- unresolved reverse-reachability paths are either resolved, explicitly
  excluded with evidence, or reported unresolved/deferred;
- no security-sensitive custom unit was silently discarded because it was
  outside the primary candidate queue.

The deterministic mapper provides coverage guidance.

Codex semantic validation remains the authority for vulnerability
existence, exploitability, business impact, severity, and confidence.

## WordPress V6.1.4 Primary and Fallback Review Queues

When V6.1.4 coverage artifacts are available, treat them as a
two-tier semantic review system.

### Primary review context

Use these artifacts as initial model-facing security review context:

- V5 candidate review units;
- V6 security-state review units;
- V6.1.4 primary orphan review units;
- V6.1.4 promoted cross-state dependencies;
- unresolved entrypoints and callbacks already identified by the mapper.

Primary queues are prioritized security hypotheses, not confirmed
vulnerabilities.

Validate them from source before reporting.

### Fallback coverage

The following artifacts preserve broader security coverage without
requiring all hypotheses to be loaded into initial model context:

- orphan-fallback-index.json;
- semantic_cross_state_hypotheses in coverage-safety-net.json;
- reverse-call information;
- unresolved or partially resolved mapper evidence.

Fallback evidence must remain available for targeted expansion.

Do not interpret absence from the primary queue as evidence that code is
safe or irrelevant.

### When to expand fallback evidence

Expand relevant fallback evidence when primary review reveals:

- unresolved authorization or capability semantics;
- custom permission callbacks;
- attacker-controlled identifiers, tokens, keys, roles, or capabilities;
- authentication or ownership transitions;
- privilege or role mutations;
- account activation, registration, recovery, or reset flows;
- state written in one component and consumed by another security-sensitive
  component;
- custom abstractions whose security semantics cannot be determined from
  primary context;
- unexplained callers or callees on a plausible attacker-to-impact path.

Expansion should be targeted to the concrete security question rather than
loading all fallback hypotheses indiscriminately.

### Cross-state interpretation

Promoted cross-state units represent state relationships worth immediate
semantic review.

They are not vulnerabilities merely because a producer and consumer share
security-relevant state.

Codex must establish:

1. attacker reachability to the producer;
2. attacker control over the relevant state;
3. missing or insufficient authorization, ownership, nonce, or validation
   controls;
4. a concrete downstream security consumer;
5. attacker-to-impact reachability.

Generic configuration state should not be promoted merely because many
functions consume it.

### Orphan interpretation

Primary orphan units represent security-sensitive custom code outside the
main V5/V6 queues.

Fallback orphan units remain coverage hypotheses.

Permission callbacks and custom authorization helpers must not be assumed
safe merely because they were placed in fallback.

When an entrypoint depends on such a helper, inspect that helper directly.

### Completion

A WordPress scan using V6.1.4 may be marked complete only when:

- all primary V5/V6/V6.1.4 review units have dispositions;
- material unresolved entrypoints and callbacks have dispositions;
- relevant fallback evidence has been expanded where primary analysis
  requires it;
- plausible cross-state attack chains have been resolved;
- custom authorization and ownership logic required by reachable paths has
  been validated;
- no security-sensitive path has been silently discarded solely because it
  was assigned to a fallback queue.

The deterministic mapper prioritizes review.

Codex semantic reasoning remains responsible for determining whether a
real vulnerability exists.
