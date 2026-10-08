import axios from "axios";
import express, { NextFunction, Request, Response } from "express";

import { Claims, verifyToken } from "./auth";
import { readingsForPatient } from "./db";

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

// SSRF: fetches an arbitrary clinician-supplied URL to "import" an external
// device report, with no allowlist or scheme/host restriction.
app.post("/reports/import", authenticate, async (req: AuthedRequest, res: Response) => {
  const url = req.body?.reportUrl;
  if (!url) return res.status(400).json({ error: "reportUrl required" });
  try {
    const resp = await axios.get(url, { timeout: 5000, maxRedirects: 5 } as any);
    res.json({ fetched: url, status: resp.status, body: resp.data });
  } catch (e: any) {
    res.status(502).json({ error: "fetch failed", detail: e?.message });
  }
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`clinician portal on :${port}`));

export default app;
