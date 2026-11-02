# Threat model and trust boundaries

## Intended use

A single analyst runs VulnPilot on a trusted local account. It accepts normalized findings and evidence and stores them on that machine. It is not an internet-facing service or an automated remediation agent.

| Boundary | Untrusted input | Control | Remaining limit |
|---|---|---|---|
| CSV intake | Asset identifiers, titles and owners | Required schema, numeric ranges, length/row caps, duplicate rejection | A valid row can still contain a false scanner assertion |
| Evidence intake | JSON snapshot and provider responses | Type/range checks, catalog counts, fixed upstream URLs | Source content is not independently authenticated beyond HTTPS |
| Browser rendering | Findings, reasons and notes | Escaping and restrictive content security policy | Browser vulnerabilities and extensions are outside scope |
| Local API | Requests from other websites | Loopback bind, exact Host/Origin checks, per-process write token, no CORS | Local programs and users are not isolated from the local service |
| Database | Imported values and workflow edits | Bound SQL parameters, transaction boundaries, explicit connection close | No encryption or tamper-evident storage |
| CSV export | Formula-like strings | Leading formula neutralization | Exported security information still requires appropriate handling |

## Network and privacy

Live enrichment contacts the fixed CISA catalog endpoint and the FIRST EPSS endpoint only after the analyst confirms in the interface. FIRST receives CVE identifiers, not asset names, owners or notes. Providers can observe the requester's network address through normal HTTPS operations. Redirects are not followed. A failed refresh retains the previous snapshot.

## Operational interpretation

Unknown evidence is provisional. Not appearing in KEV does not establish safety. EPSS is not an asset-specific compromise probability. Priority weights and target dates are illustrative policy choices. Analysts must validate applicability, scope, compensating controls and vendor remediation guidance. Marking a finding resolved does not establish that a patch was installed.

## Out of scope

Public deployment, hostile multi-user access, endpoint compromise, scanner execution, patch execution, SSO/RBAC, cross-tenant isolation, cryptographically protected audit trails and high-volume ingestion need a different architecture and independent security review.
