# WordPress Plugin Threat Model

Target: WordPress plugins.

Attacker priority:
1. Unauthenticated
2. Subscriber
3. Contributor

Primary security boundaries:

HTTP-controlled input
-> WordPress entrypoint
-> Authentication
-> Capability / ownership / nonce controls
-> Plugin logic
-> Sensitive sink

Do not spend scan budget building a generic threat model when this
WordPress-specific threat model is sufficient.

Prioritize the minimum attacker privilege required to reach a path.
