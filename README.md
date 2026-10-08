# cardiolink-clinician-portal

Web portal where cardiologists review CardioLink device readings and import
external device reports.

- `GET /patients/:id/readings` — per-patient reading history.
- `POST /reports/import` `{ "reportUrl": "..." }` — pulls an external report by URL.

Auth tokens are the shared HS256 tokens issued by `cardiolink-shared-auth`.
