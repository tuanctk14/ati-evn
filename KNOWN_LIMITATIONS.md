# Known limitations

## Slice 10 — LeakCheck credential monitoring: deferred

Slice 10 planned to integrate LeakCheck for credential-leak monitoring
(domain-wide weekly scans across 8 EVN subsidiary domains, per-breach
password/hash intel, a `CredentialLeak` entity, and a YAML rule engine
keyed on password hash strength).

Verified live against the real LeakCheck API before writing any code:
the only endpoint reachable without a paid plan is the **Public API**
(`https://leakcheck.io/api/public?check=...`, unauthenticated, rate
limited to 1 req/s). It differs from the plan's assumptions in ways
that make the design infeasible as specified:

- **Email-only.** No domain search on any tier below Enterprise — every
  `/v2/query/{domain}?type=domain` call returned `403 Active plan
  required`, confirmed against two different API keys.
- **Aggregate, not per-breach.** A lookup returns one aggregate
  `fields: [...]` (data categories exposed, e.g. `"password"`,
  `"phone"`) and `sources: [{name, date}]` across *all* matching
  breaches for that identifier — never a per-breach row, and never an
  actual password or hash value.

This breaks the weekly domain-rotation scheduler (no domain search
exists to rotate), the `CredentialLeak` per-(email, source, breach_date)
schema (the API can't populate it), and the rule engine's severity
logic (`password_hash_type`, `password_included` per record — not
available from this endpoint).

Full implementation requires LeakCheck Pro/Enterprise or an equivalent
commercial provider with per-breach, per-domain access.

**Report impact (slice 8):** the "Lộ lọt tài khoản" (credential leak)
section should render `N/A — chưa tích hợp` with a note that this
requires a commercial API tier, rather than fabricating data.
