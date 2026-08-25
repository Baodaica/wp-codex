# WP Codex Security

Experimental WordPress-focused security scanning workflow built on top of
OpenAI Codex Security.

WP Codex Security combines deterministic WordPress attack-surface mapping
with bounded call/dataflow analysis and Codex semantic security validation.

The goal is to reduce unnecessary repository-wide model exploration while
preserving the reasoning capabilities required to discover and validate
real WordPress vulnerabilities.

> **Status:** Experimental / research project. Findings should be manually
> validated before disclosure or bug-bounty submission.

---

## Overview

Traditional LLM-based source review can spend substantial context, time,
and cost rediscovering a repository's structure before reaching the
security-sensitive code.

WP Codex Security introduces a WordPress-specific discovery layer:

```text
WordPress Plugin
       |
       v
Deterministic Security Surface Mapping
       |
       v
Entrypoint / Callback Resolution
       |
       v
Security-Relevant Call Graph
       |
       v
Source / Control / Effect Analysis
       |
       v
Bounded Interprocedural Flow Analysis
       |
       +--------------------+
       |                    |
       v                    v
review-index.json      gap-index.json
       |                    |
       +---------+----------+
                 |
                 v
       Codex Semantic Validation
                 |
                 v
        Validated Findings
```

The deterministic mapper handles repetitive discovery work while Codex
remains responsible for semantic validation, exploitability reasoning,
business-logic analysis, attack-chain reasoning, counter-evidence, severity,
and confidence.

---

## Design Goals

The WordPress V5 workflow is designed around several principles:

- Avoid repeating repository-wide discovery when deterministic analysis
  already provides source anchors.
- Model WordPress entrypoints and security-sensitive effects explicitly.
- Prioritize attacker-to-impact reachability rather than raw sink counts.
- Preserve unresolved paths instead of silently discarding them.
- Use compact model-facing review queues to reduce unnecessary context.
- Allow targeted source expansion when semantic validation requires it.
- Preserve Codex Security's deeper reasoning for novel vulnerability classes
  and business-logic vulnerabilities.
- Avoid treating heuristic score alone as proof of vulnerability.
- Avoid treating a low score as sufficient reason to silently drop a path.

---

## WordPress Security Graph V5

The main WordPress mapper is:

```text
wp-codex-security-plugin/scripts/wordpress/wp_candidate_map_v5.py
```

It performs several stages of analysis.

### 1. WordPress Registration Discovery

The mapper identifies WordPress registration surfaces and attempts to
normalize their callbacks.

Examples include:

```text
REST API routes
wp_ajax_* actions
wp_ajax_nopriv_* actions
admin-post actions
init
wp_loaded
template_redirect
WordPress actions and filters
```

Dynamic registrations that cannot be safely resolved are tracked separately.

### 2. Callback Resolution

Callbacks are normalized and connected to indexed PHP functions.

The resolver performs bounded handling of dynamic hooks and callbacks instead
of requiring the model to rediscover all registration relationships manually.

### 3. Security Profiling

Reachable callbacks are analyzed for security-relevant signals such as:

```text
request-controlled input
database operations
configuration writes
file operations
uploads
dynamic includes
object lookups
redirects
HTTP responses
authorization controls
nonce checks
signature checks
validation and sanitization
```

### 4. Interprocedural Flow Analysis

V5 includes lightweight bounded interprocedural analysis to identify likely
request-to-effect paths.

Flow confidence is used to help prioritize semantic review, but deterministic
flow classification is not treated as final vulnerability proof.

### 5. Compact Review Queue

Instead of feeding the complete security graph to the model, V5 generates a
small model-facing queue.

This allows Codex to start from security-relevant paths rather than repeatedly
enumerating the entire repository.

---

## V5 Output

Running the mapper creates:

```text
wpsec-output/<plugin>/v5/
```

with four primary artifacts.

### `summary.json`

Compact statistics for the mapped plugin.

Typical information includes:

```text
indexed functions
raw registrations
resolved registration variants
registration gaps
review units
model-facing gaps
flow confidence
review effort
resolver statistics
```

### `review-index.json`

The primary model-facing security review queue.

This contains compact review units representing security-relevant execution
paths that should receive semantic validation.

Codex should use this file as the initial V5 investigation queue.

### `gap-index.json`

Contains unresolved security-relevant paths that deterministic analysis could
not safely resolve.

These paths require bounded semantic investigation.

An unresolved path must not be silently treated as safe.

### `security-graph.json`

Full deterministic graph and supporting evidence.

This artifact is intended primarily for targeted drill-down.

It should **not** normally be loaded wholesale into the model context.

---

## Relationship to the Previous Candidate Mapper

The repository also contains the previous candidate-oriented workflow.

V5 is designed to move from:

```text
sink candidate
    ->
candidate review
```

toward:

```text
WordPress exposure
    ->
reachable callback
    ->
attacker-controlled data
    ->
security controls
    ->
security-sensitive effect
    ->
semantic validation
```

The older candidate artifacts may still be generated and can be used as
fallback or supplementary evidence.

---

## Requirements

Recommended environment:

```text
Linux
Node.js >= 22
Python 3
pnpm
Git
Codex Security authentication
```

The current development environment has primarily been tested against local
WordPress plugin source trees.

---

## Installation

Clone the repository:

```bash
git clone git@github.com:Baodaica/wp-codex.git
cd wp-codex
```

Checkout the WordPress development branch if it is not already the default:

```bash
git checkout wordpress-security
```

Install the TypeScript SDK dependencies:

```bash
cd sdk/typescript

corepack enable
pnpm install
```

Return to the repository root:

```bash
cd ../..
```

Verify the CLI:

```bash
node sdk/typescript/bin/codex-security.mjs --help
```

---

## Authentication

Codex Security must be authenticated before scanning.

Use an authentication method supported by the upstream Codex Security CLI.

Do not commit API keys, authentication state, tokens, scan state, or other
credentials to this repository.

---

## Running a WordPress Security Scan

Assume a WordPress plugin is installed at:

```text
/opt/lampp/htdocs/wordpress/wp-content/plugins/example-plugin
```

Set the target:

```bash
PLUGIN="/opt/lampp/htdocs/wordpress/wp-content/plugins/example-plugin"
```

Then run:

```bash
node \
sdk/typescript/bin/codex-security.mjs \
scan \
"$PLUGIN" \
--plugin-path /opt/codex-security/wp-codex-security-plugin \
--mode standard \
--effort high \
--codex 'features.multi_agent_v2.max_concurrent_threads_per_session=1' \
--max-cost 5
```

If your repository is cloned somewhere other than `/opt/codex-security`,
replace the `--plugin-path` value accordingly.

For example:

```bash
REPO="/path/to/wp-codex"
PLUGIN="/path/to/wordpress/wp-content/plugins/example-plugin"

node \
"$REPO/sdk/typescript/bin/codex-security.mjs" \
scan \
"$PLUGIN" \
--plugin-path "$REPO/wp-codex-security-plugin" \
--mode standard \
--effort high \
--codex 'features.multi_agent_v2.max_concurrent_threads_per_session=1' \
--max-cost 5
```

---

## Cost Limit

`--max-cost` is a safety limit, not a requirement.

Example:

```text
--max-cost 5
```

stops the scan when estimated model cost exceeds the configured limit.

For larger or more complex plugins, increase the value:

```text
--max-cost 10
```

or use another limit appropriate for the review.

A low cost limit can cause validation work to remain incomplete.

Never interpret a cost-limited partial scan as evidence that the plugin is
secure.

---

## Effort

A practical default for WordPress review is:

```text
--effort high
```

Higher reasoning effort may improve difficult semantic validation but can
increase runtime and model usage.

For particularly difficult investigations, an environment may choose a higher
supported effort level.

---

## Multi-Agent Behavior

A conservative configuration used during development is:

```text
--codex 'features.multi_agent_v2.max_concurrent_threads_per_session=1'
```

This reduces duplicate exploration by concurrent investigators.

The V5 workflow is intended to provide bounded review units so that future
multi-agent configurations can partition work by security unit rather than
launching redundant repository-wide audits.

---

## Manual Mapper Execution

The deterministic mapper can also be executed independently.

```bash
python3 \
wp-codex-security-plugin/scripts/wordpress/wp_candidate_map_v5.py \
/path/to/wordpress/wp-content/plugins/example-plugin
```

Example:

```bash
PLUGIN="/opt/lampp/htdocs/wordpress/wp-content/plugins/example-plugin"

python3 \
wp-codex-security-plugin/scripts/wordpress/wp_candidate_map_v5.py \
"$PLUGIN"
```

Inspect the summary:

```bash
python3 -m json.tool \
wpsec-output/example-plugin/v5/summary.json
```

Inspect the compact review queue:

```bash
python3 -m json.tool \
wpsec-output/example-plugin/v5/review-index.json
```

Inspect unresolved model-facing gaps:

```bash
python3 -m json.tool \
wpsec-output/example-plugin/v5/gap-index.json
```

---

## Security Review Semantics

A V5 review is not considered complete merely because the mapper finished.

The semantic review should ensure:

1. Every review unit receives a disposition.
2. Every model-facing gap is resolved, explicitly excluded with evidence, or
   reported as unresolved/deferred.
3. Plausible findings are traced from attacker-controlled exposure to
   security-sensitive impact.
4. Relevant authorization and validation controls are checked.
5. Counter-evidence is considered before reporting.
6. Low-priority or unknown-flow units are not silently discarded.
7. Static-analysis uncertainty remains explicit.

---

## What V5 Does Not Replace

The deterministic graph is an optimization and discovery mechanism.

It does **not** replace:

```text
semantic source-code reasoning
business-logic analysis
authorization reasoning
attack-chain analysis
framework behavior validation
counter-evidence analysis
severity assessment
confidence assessment
manual vulnerability validation
```

A deterministic source-to-sink path is a candidate for investigation, not
automatically a vulnerability.

Likewise, absence of a deterministic path is not absolute proof that no
vulnerability exists.

---

## Novel Vulnerabilities

The mapper intentionally does not attempt to encode every possible WordPress
vulnerability pattern.

Novel vulnerabilities may depend on:

```text
business logic
cross-component trust
unexpected state transitions
object ownership
framework semantics
token exposure
authorization composition
multi-step attack chains
plugin-to-plugin interaction
WordPress or WooCommerce behavior
```

When deterministic evidence indicates an unresolved security boundary, Codex
may expand the investigation beyond the compact unit.

The expansion should remain evidence-driven rather than restarting an
unbounded repository-wide audit.

---

## Example Development Result

During development, the workflow was tested against multiple WordPress
plugins.

In one test, semantic validation identified an unauthenticated order-related
information exposure path involving a WooCommerce order key.

The resulting assessment was:

```text
Severity:   Medium
CVSS:       6.5
Confidence: High
```

Severity and confidence are intentionally separate concepts.

`Medium / CVSS 6.5` describes estimated vulnerability impact and
exploitability.

`High confidence` describes confidence that the static-analysis conclusion is
correct.

This example is provided only to illustrate the workflow and is not a
performance or vulnerability-detection guarantee.

---

## Performance

The V5 architecture is intended to reduce model context consumed by repetitive
repository discovery.

Actual:

```text
runtime
token usage
cache usage
model cost
number of review units
number of findings
```

vary substantially depending on plugin architecture, size, framework usage,
dynamic PHP behavior, model configuration, and scan effort.

No fixed cost or vulnerability-coverage guarantee is implied.

---

## Repository Layout

Important WordPress-specific components:

```text
wp-codex-security-plugin/
|
+-- scripts/
|   +-- wordpress/
|       +-- wp_candidate_map_v5.py
|
+-- skills/
    +-- security-scan/
        +-- SKILL.md
```

Local mapper output:

```text
wpsec-output/
```

is excluded from Git and should not be committed.

---

## Updating Your Local Branch

After modifying the WordPress workflow:

```bash
git status

git add <files>

git commit -m "Describe the change"

git push
```

The `wordpress-security` branch can track the personal repository while an
upstream remote can remain configured for synchronizing future Codex Security
changes.

---

## Security and Responsible Use

Use this project only on software you own or are explicitly authorized to
review.

Static-analysis findings should be independently validated before disclosure.

Do not treat automatically generated findings as sufficient evidence for a
public vulnerability claim.

Do not commit:

```text
API keys
GitHub tokens
authentication state
customer source code
private scan artifacts
sensitive vulnerability evidence
credentials
```

---

## Upstream Project

This project is based on OpenAI Codex Security.

The WordPress-specific security graph, candidate-first orchestration,
review-index workflow, bounded WordPress analysis, and related experimental
changes in this repository are extensions developed on top of the upstream
project.

For upstream Codex Security documentation and current platform behavior,
consult the official OpenAI Codex Security project and documentation.

This repository is an independent experimental project and is not an official
OpenAI-maintained WordPress security scanner.

---

## License

This repository retains the upstream Apache-2.0 license.

See:

```text
LICENSE
```

for license terms.
