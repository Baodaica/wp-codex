# WP Codex Security

Experimental WordPress-focused security scanner built on top of Codex Security.

The project adds deterministic WordPress security discovery before Codex semantic review. The goal is to reduce unnecessary repository-wide exploration while preserving coverage for classic vulnerabilities, authorization issues, privilege escalation, account takeover, and custom WordPress business-logic bugs.

> Experimental project. Mapper output is review guidance, not a confirmed vulnerability report.

## Architecture

```text
WordPress Plugin
      |
      v
PHP / Function Index
      |
      v
WordPress Entrypoint Discovery
      |
      +--> AJAX / AJAX nopriv
      +--> admin-post
      +--> REST routes
      +--> callbacks / permission callbacks
      |
      v
V5 Security Graph
      |
      +--> request sources
      +--> security controls
      +--> sensitive effects / sinks
      +--> bounded call/dataflow analysis
      +--> candidates + unresolved gaps
      |
      v
V6 Security State Graph
      |
      +--> authentication / authorization
      +--> roles / capabilities / permissions
      +--> ownership / account state
      +--> registration / activation / reset
      +--> tokens / secrets
      +--> security-sensitive configuration
      |
      v
V6.1 Coverage Safety Net
      |
      +--> reverse call analysis
      +--> orphan security functions
      +--> custom authorization helpers
      +--> state writers / readers
      +--> cross-request state relationships
      |
      v
V6.1.2 Concrete State Keys
      |
      +--> option:key
      +--> user_meta:key
      +--> post_meta:key
      |
      v
V6.1.3 Security-Aware Filtering
      |
      +--> reduce generic configuration noise
      +--> prioritize security-relevant state
      |
      v
V6.1.4 Review Queues
      |
      +--> PRIMARY: V5 candidates, V6 state units, important orphan units, promoted cross-state paths
      |
      +--> FALLBACK: lower-priority orphan hypotheses, semantic cross-state hypotheses, reverse-call evidence, unresolved security logic
      |
      v
Codex Semantic Validation
      |
      +--> attacker reachability
      +--> attacker-controlled data/state
      +--> capability / authorization checks
      +--> ownership validation
      +--> nonce semantics
      +--> business-logic reasoning
      +--> multi-request attack chains
      +--> counter-evidence
      |
      v
Validated Findings
```

## Important Design Rule

Candidate mapping is a prioritization mechanism, not a hard security boundary.

```text
No candidate != no vulnerability
High score    != confirmed vulnerability
Fallback      != safe
```

Codex may follow relevant helpers, callers, state consumers, permission callbacks, and fallback evidence whenever required to validate a concrete security path.

This is especially important for privilege escalation, account takeover, authorization or ownership bypass, role/capability manipulation, insecure permission callbacks, token trust failures, registration/recovery logic, cross-request state manipulation, and custom plugin security abstractions.

## Main Mapper

```text
wp-codex-security-plugin/scripts/wordpress/wp_candidate_map_v5.py
```

The filename remains `wp_candidate_map_v5.py`, but the current implementation contains V5, V6, and V6.1.x analysis layers.

WordPress scan orchestration is defined in:

```text
wp-codex-security-plugin/skills/security-scan/SKILL.md
```

## Requirements

- Node.js 22.13.0+
- Python 3.10+
- Codex Security
- Local WordPress plugin source

Example plugin path:

```text
/opt/lampp/htdocs/wordpress/wp-content/plugins/example-plugin
```

## Usage

Run a full scan:

<<<<<<< ours
```bash
cd /opt/codex-security

PLUGIN="/opt/lampp/htdocs/wordpress/wp-content/plugins/example-plugin"

node \
sdk/typescript/bin/codex-security.mjs \
scan \
"$PLUGIN" \
--plugin-path /opt/codex-security/wp-codex-security-plugin \
--mode standard \
--effort high \
--codex 'features.multi_agent_v2.max_concurrent_threads_per_session=1'
```

Omit `--max-cost` if you do not want a scan cost limit.
=======
For individual CLI stages with durable state and access to a separately deployed
findings service, use the same scanner image with the
[workflow runner Compose example](docker/README.md#workflow-runner).

## Findings service (preview)

Run `codex-security serve` to start the service without Docker. See
[running without Docker](sdk/typescript/README.md#running-without-docker)
for prerequisites, credentials, and storage configuration.

The [findings service](sdk/typescript/README.md#findings-service-preview) runs
from the same `ghcr.io/openai/codex-security` image as the scanner (or a local
source build), with a separate container and state volume configured by
`compose.findings.yaml`. It stores findings and embeddings in SQLite and lists
findings with pagination. Its read-only dashboard at `/dashboard` refreshes every
five seconds and shows stored findings and duplicate groups from the service's
database. It also returns potential duplicates by embedding similarity within a
repository or an explicit all-repository scope. The
`codex-security publish scan --to custom --findings-url http://localhost:3000`
command uploads completed findings and their repository ID. The SDK and
`codex-security dedupe` command retrieve candidates, run independent Codex
reviews locally, and persist accepted duplicate groups; `--all-repositories`
opts into the broader scope.

Use `codex-security classify-severity --scan SCAN_ID --rubric /path/to/policy.md`
to assess selected findings under your own policy before publishing tickets.
Scan classification checkpoints each finding in SQLite and reuses matching
assessments on reruns; `--reprocess` forces reassessment. The SDK exposes the same
classification operation; original scan severity stays unchanged. See [severity classification](sdk/typescript/README.md#classify-finding-severity).

## Other providers
>>>>>>> theirs

Run only the deterministic WordPress mapper:

```bash
cd /opt/codex-security

PLUGIN="/opt/lampp/htdocs/wordpress/wp-content/plugins/example-plugin"

python3 \
wp-codex-security-plugin/scripts/wordpress/wp_candidate_map_v5.py \
"$PLUGIN"
```

Typical mapper phases:

```text
[*] Indexing PHP functions...
[*] Resolving AJAX/admin-post entrypoints...
[*] Resolving REST entrypoints...
[*] Building V5 security graph...
[*] Building V6 security state graph...
[*] Building V6.1 coverage safety net...
[*] Generating candidates...
```

## Output

Artifacts are written under:

```text
wpsec-output/<plugin>/
```

Important current artifacts include:

```text
wpsec-output/<plugin>/
├── v6/
│   ├── review-index.json
│   ├── security-state-graph.json
│   └── summary.json
└── v6.1/
    ├── coverage-safety-net.json
    ├── cross-state-index.json
    ├── orphan-review-index.json
    ├── orphan-fallback-index.json
    └── summary.json
```

These are intermediate analysis artifacts, not vulnerability reports.

## Scope

The V5/V6/V6.1.x extensions are specifically designed for WordPress plugin security research. The underlying Codex Security engine remains general-purpose.

## Limitations

Static analysis cannot perfectly resolve all dynamic PHP and WordPress behavior. Dynamic callbacks, generated hooks, runtime state, custom frameworks, external integrations, custom storage abstractions, and complex business logic may require additional semantic or dynamic validation.

Therefore:

```text
No mapper candidate != proof of safety
Mapper candidate    != proof of vulnerability
```

## Experimental Status

This repository is an independent experimental WordPress-focused extension of Codex Security intended for authorized security research.

Findings should be manually validated before public disclosure, CVE submission, or bug-bounty submission.

## License

This repository retains the upstream Apache-2.0 license. See `LICENSE`.
