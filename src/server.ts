import express, { NextFunction, Request, Response } from "express";

import { Claims, verifyToken } from "./auth";
import { readingsForPatient } from "./db";
import { ReportUrlError, allowedReportHosts, fetchReport, validateReportUrl } from "./reportFetch";

const app = express();
app.use(express.json());

interface AuthedRequest extends Request {
  claims?: Claims;
}

function authenticate(req: AuthedRequest, res: Response, next: NextFunction) {
  const header = req.header("authorization") || "";
  const token = header.replace(/^Bearer\s+/i, "");
  try {
    req.claims = verifyToken(token);
    next();
  } catch (e) {
    res.status(401).json({ error: "invalid token" });
  }
}

app.get("/health", (_req, res) => res.json({ ok: true }));

// IDOR: any authenticated clinician can read any patient's readings; the
// patient->clinician assignment is never checked.
app.get("/patients/:id/readings", authenticate, (req: AuthedRequest, res: Response) => {
  res.json({ patient: req.params.id, readings: readingsForPatient(req.params.id) });
});

// Imports an external device report. Only https URLs on the REPORT_PROVIDER_HOSTS
// allow-list are fetched; private/link-local/metadata addresses are refused at
// connect time, redirects are not followed, and upstream errors are not echoed.
app.post("/reports/import", authenticate, async (req: AuthedRequest, res: Response) => {
  const raw = req.body?.reportUrl;
  if (!raw) return res.status(400).json({ error: "reportUrl required" });
  let url: URL;
  try {
    url = validateReportUrl(raw, allowedReportHosts());
  } catch (e) {
    const reason = e instanceof ReportUrlError ? e.message : "reportUrl not allowed";
    return res.status(400).json({ error: reason });
  }
  try {
    const report = await fetchReport(url);
    res.json({ fetched: url.toString(), status: report.status, body: report.body });
  } catch (e: any) {
    console.error(`report import from ${url.host} failed: ${e?.message}`);
    res.status(502).json({ error: "fetch failed" });
  }
});

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => console.log(`clinician portal on :${port}`));
}

export default app;
