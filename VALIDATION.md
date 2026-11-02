# Verification record

Verified on November 2, 2026 with Python 3.12.14:

- All 15 automated workflow and HTTP-handler tests passed.
- JavaScript passed `node --check`.
- The Python HTTP server initialized and bound successfully.

HTTP tests exercise the real request handler and response parser using in-memory sockets. The managed creation environment blocks local socket connections, so browser-to-server integration and live upstream network refresh could not be verified end to end here. Live enrichment is covered with mocked provider responses, including preservation of previous evidence after a failed fetch.

Run locally using the README instructions, then verify import, filtering, workflow updates, persistence and exports. Use actual permitted CVEs and network access to verify the upstream refresh. Synthetic sample data does not establish operational effectiveness or detection performance.
