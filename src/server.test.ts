import assert from "node:assert/strict";
import http from "node:http";
import { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import { issueToken } from "./auth";
import app from "./server";

const IMDS_PATH = "/latest/meta-data/iam/security-credentials/cardiolink-clinician-portal";
const SECRET_MARKER = "SecretAccessKey";

describe("POST /reports/import", () => {
  let portal: http.Server;
  let imds: http.Server;
  let portalUrl: string;
  let imdsHits = 0;
  const token = issueToken({ sub: "dr-house", role: "clinician" });

  before(async () => {
    process.env.REPORT_PROVIDER_HOSTS = "reports.provider.invalid";
    imds = http.createServer((_req, res) => {
      imdsHits++;
      res.end(JSON.stringify({ AccessKeyId: "AKIA-FAKE", [SECRET_MARKER]: "fake-secret", Token: "fake" }));
    });
    await new Promise<void>((r) => imds.listen(0, "127.0.0.1", r));
    portal = app.listen(0);
    await new Promise<void>((r) => portal.once("listening", r));
    portalUrl = `http://127.0.0.1:${(portal.address() as AddressInfo).port}`;
  });

  after(() => {
    portal.close();
    imds.close();
    delete process.env.REPORT_PROVIDER_HOSTS;
  });

  async function importReport(reportUrl: unknown, auth = true) {
    const res = await fetch(`${portalUrl}/reports/import`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(auth ? { authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ reportUrl }),
    });
    return { status: res.status, text: await res.text() };
  }

  it("does not fetch or echo the IMDS credential document (the reported attack)", async () => {
    const imdsPort = (imds.address() as AddressInfo).port;
    for (const target of [
      `http://169.254.169.254${IMDS_PATH}`,
      `http://127.0.0.1:${imdsPort}${IMDS_PATH}`,
      `https://127.0.0.1:${imdsPort}${IMDS_PATH}`,
      `http://[::ffff:127.0.0.1]:${imdsPort}${IMDS_PATH}`,
    ]) {
      const r = await importReport(target);
      assert.equal(r.status, 400, target);
      assert.ok(!r.text.includes(SECRET_MARKER), target);
    }
    assert.equal(imdsHits, 0);
  });

  it("does not act as a port-scan oracle against internal services", async () => {
    for (const target of ["http://gateway:8080/health", "http://s3:9000/", "https://gateway:8080/health"]) {
      const r = await importReport(target);
      assert.equal(r.status, 400, target);
      assert.ok(!/ECONNREFUSED|ENOTFOUND|getaddrinfo/.test(r.text), target);
    }
  });

  it("still requires reportUrl", async () => {
    const r = await importReport(undefined);
    assert.equal(r.status, 400);
    assert.match(r.text, /reportUrl required/);
  });

  it("does not leak upstream error details when an allow-listed fetch fails", async () => {
    // Allow-listed host under the reserved .invalid TLD (RFC 2606), so DNS
    // deterministically fails; the caller must only see a generic error.
    const r = await importReport("https://reports.provider.invalid/exports/1.json");
    assert.equal(r.status, 502);
    assert.equal(r.text, JSON.stringify({ error: "fetch failed" }));
  });
});
