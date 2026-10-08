# cardiolink-clinician-portal

Web portal where cardiologists review CardioLink device readings and import
external device reports.

- `GET /patients/:id/readings` — per-patient reading history.
- `POST /reports/import` `{ "reportUrl": "..." }` — pulls an external report by URL.
  Only `https` URLs whose `host[:port]` is listed in the comma-separated
  `REPORT_PROVIDER_HOSTS` environment variable are fetched (unset = deny all).
  Redirects are not followed and hosts resolving to private, loopback or
  link-local (e.g. 169.254.169.254) addresses are refused.

Run `npm test` for the test suite.

Auth tokens are the shared HS256 tokens issued by `cardiolink-shared-auth`.
