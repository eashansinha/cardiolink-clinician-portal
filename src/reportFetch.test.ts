import assert from "node:assert/strict";
import http from "node:http";
import { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import {
  ReportUrlError,
  allowedReportHosts,
  fetchReport,
  guardedLookup,
  isPublicAddress,
  validateReportUrl,
} from "./reportFetch";

const ALLOWED = allowedReportHosts("reports.provider.example, Legacy.Provider.Example:8443");

describe("isPublicAddress", () => {
  it("rejects loopback, private, link-local, metadata and reserved ranges", () => {
    for (const ip of [
      "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254",
      "169.254.170.2", "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "192.0.2.1",
      "::1", "::", "fe80::1", "fd00::1", "fc00::1", "ff02::1", "::ffff:169.254.169.254",
      "::ffff:127.0.0.1", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1", "not-an-ip",
    ]) {
      assert.equal(isPublicAddress(ip), false, ip);
    }
  });

  it("accepts globally routable unicast addresses", () => {
    for (const ip of ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"]) {
      assert.equal(isPublicAddress(ip), true, ip);
    }
  });
});

describe("validateReportUrl", () => {
  it("accepts https URLs on the allow-list, case-insensitively", () => {
    assert.equal(
      validateReportUrl("https://reports.provider.example/exports/42.json#frag", ALLOWED).toString(),
      "https://reports.provider.example/exports/42.json",
    );
    assert.equal(
      validateReportUrl("https://legacy.provider.example:8443/r", ALLOWED).host,
      "legacy.provider.example:8443",
    );
  });

  it("rejects the IMDS URL and every other non-allow-listed destination", () => {
    const bad = [
      "http://169.254.169.254/latest/meta-data/iam/security-credentials/cardiolink-clinician-portal",
      "https://169.254.169.254/latest/meta-data/",
      "https://[fd00::1]/",
      "https://[::ffff:169.254.169.254]/",
      "http://reports.provider.example/r", // allow-listed host but plain http
      "https://reports.provider.example:444/r", // allow-listed host, different port
      "https://evil.example/r",
      "https://reports.provider.example.evil.example/r",
      "https://user:pw@reports.provider.example/r",
      "file:///etc/passwd",
      "gopher://gateway:8080/_x",
      "http://gateway:8080/health",
      "http://s3:9000/",
      "",
      "not a url",
      42,
      { href: "https://reports.provider.example/" },
      "https://" + "a".repeat(3000),
    ];
    for (const url of bad) {
      assert.throws(() => validateReportUrl(url, ALLOWED), ReportUrlError, String(url));
    }
  });

  it("denies everything when the allow-list is empty", () => {
    assert.throws(() => validateReportUrl("https://reports.provider.example/r", allowedReportHosts("")), ReportUrlError);
    assert.throws(() => validateReportUrl("https://reports.provider.example/r", allowedReportHosts()), ReportUrlError);
  });
});

function fakeLookup(answers: Array<{ address: string; family: number }>) {
  return ((_host: string, _opts: unknown, cb: (e: Error | null, a: unknown) => void) => cb(null, answers)) as any;
}

describe("guardedLookup", () => {
  it("passes public answers through", async () => {
    const lookup = guardedLookup(fakeLookup([{ address: "93.184.216.34", family: 4 }]));
    const result = await new Promise<[string, number]>((resolve, reject) =>
      (lookup as any)("reports.provider.example", {}, (e: Error | null, a: string, f: number) =>
        e ? reject(e) : resolve([a, f])),
    );
    assert.deepEqual(result, ["93.184.216.34", 4]);
  });

  it("refuses when any answer is non-public (DNS rebinding / internal CNAME)", async () => {
    const lookup = guardedLookup(fakeLookup([{ address: "93.184.216.34", family: 4 }, { address: "169.254.169.254", family: 4 }]));
    await assert.rejects(
      new Promise((resolve, reject) =>
        (lookup as any)("reports.provider.example", { all: true }, (e: Error | null, a: unknown) => (e ? reject(e) : resolve(a))),
      ),
      ReportUrlError,
    );
  });
});

describe("fetchReport", () => {
  let imds: http.Server;
  let imdsPort: number;
  let hits = 0;

  before(async () => {
    imds = http.createServer((_req, res) => {
      hits++;
      res.end(JSON.stringify({ AccessKeyId: "AKIA-FAKE", SecretAccessKey: "fake", Token: "fake" }));
    });
    await new Promise<void>((r) => imds.listen(0, "127.0.0.1", r));
    imdsPort = (imds.address() as AddressInfo).port;
  });
  after(() => imds.close());

  it("never connects when an allow-listed name resolves to an internal address", async () => {
    const url = new URL(`https://reports.provider.example:${imdsPort}/latest/meta-data/iam/security-credentials/`);
    await assert.rejects(fetchReport(url, fakeLookup([{ address: "127.0.0.1", family: 4 }])), /non-public address/);
    assert.equal(hits, 0);
  });
});
