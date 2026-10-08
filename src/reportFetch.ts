import dns from "node:dns";
import https from "node:https";
import net from "node:net";
import axios from "axios";

/** Thrown when a reportUrl is rejected before any network connection is made. */
export class ReportUrlError extends Error {}

const MAX_REPORT_BYTES = 5 * 1024 * 1024;
const MAX_URL_LENGTH = 2048;
const FETCH_TIMEOUT_MS = 5000;

/**
 * Hosts (host[:port]) that `/reports/import` may fetch from. Empty => deny all.
 * An explicit `:443` is dropped so entries compare equal to `URL.host`, which
 * omits the default https port.
 */
export function allowedReportHosts(raw: string = process.env.REPORT_PROVIDER_HOSTS || ""): Set<string> {
  return new Set(
    raw
      .split(",")
      .map((h) => h.trim().toLowerCase().replace(/:443$/, ""))
      .filter(Boolean),
  );
}

function isPublicV4(ip: string): boolean {
  const octets = ip.split(".").map(Number);
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return false;
  const [a, b] = octets;
  if (a === 0 || a === 10 || a === 127) return false; // this-network, private, loopback
  if (a === 100 && b >= 64 && b <= 127) return false; // shared address space
  if (a === 169 && b === 254) return false; // link-local, incl. 169.254.169.254 (IMDS)
  if (a === 172 && b >= 16 && b <= 31) return false; // private
  if (a === 192 && (b === 0 || b === 168)) return false; // IETF assignments / TEST-NET-1, private
  if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
  if (a >= 224) return false; // multicast, reserved, broadcast
  return true;
}

function expandV6(ip: string): number[] | null {
  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
  const groups = [...head, ...Array(missing).fill("0"), ...tail];
  const parsed = groups.map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN));
  return parsed.some(Number.isNaN) ? null : parsed;
}

function embeddedV4(hi: number, lo: number): string {
  return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
}

function isPublicV6(ip: string): boolean {
  const lower = ip.toLowerCase().replace(/%.*$/, "");
  const mapped = /^(?:0*:)*ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
  if (mapped) return isPublicV4(mapped[1]);
  if (lower.includes(".")) return false; // other embedded-IPv4 forms: reject conservatively
  const g = expandV6(lower);
  if (!g) return false;
  if (g.slice(0, 5).every((x) => x === 0)) {
    // ::/96 (unspecified, loopback, deprecated IPv4-compatible) and
    // ::ffff:0:0/96 (IPv4-mapped, hex form e.g. ::ffff:7f00:1)
    if (g[5] === 0xffff) return isPublicV4(embeddedV4(g[6], g[7]));
    return false;
  }
  if ((g[0] & 0xfe00) === 0xfc00) return false; // fc00::/7 unique local
  if ((g[0] & 0xffc0) === 0xfe80) return false; // fe80::/10 link-local
  if ((g[0] & 0xff00) === 0xff00) return false; // ff00::/8 multicast
  if (g[0] === 0x0064 && g[1] === 0xff9b) return false; // 64:ff9b::/96 and 64:ff9b:1::/48 NAT64
  if (g[0] === 0x2001 && g[1] === 0x0000) return false; // 2001::/32 Teredo
  if (g[0] === 0x2002) return false; // 2002::/16 6to4
  return true;
}

/** True only for globally routable unicast addresses. Anything unparseable is non-public. */
export function isPublicAddress(ip: string): boolean {
  const family = net.isIP(ip);
  if (family === 4) return isPublicV4(ip);
  if (family === 6) return isPublicV6(ip);
  return false;
}

/**
 * Parses and allow-lists a clinician-supplied report URL. Only https URLs whose
 * host[:port] is in `allowed` pass; IP literals and embedded credentials never do.
 */
export function validateReportUrl(raw: unknown, allowed: Set<string>): URL {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_URL_LENGTH) {
    throw new ReportUrlError("reportUrl must be a string");
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ReportUrlError("reportUrl is not a valid URL");
  }
  if (url.protocol !== "https:") throw new ReportUrlError("reportUrl must use https");
  if (url.username || url.password) throw new ReportUrlError("reportUrl must not contain credentials");
  if (net.isIP(url.hostname.replace(/^\[|\]$/g, "")) !== 0) {
    throw new ReportUrlError("reportUrl must name an approved report provider, not an IP address");
  }
  if (!allowed.has(url.host.toLowerCase())) {
    throw new ReportUrlError("reportUrl host is not an approved report provider");
  }
  url.hash = "";
  return url;
}

export type LookupFn = typeof dns.lookup;

/**
 * Wraps dns.lookup so the address the socket actually connects to is checked:
 * if any answer for the host is private, loopback, link-local or otherwise
 * non-public, the connection is refused. Defeats DNS rebinding and allow-listed
 * names that point at internal services.
 */
export function guardedLookup(base: LookupFn = dns.lookup): LookupFn {
  const guarded = (hostname: string, options: any, callback: any) => {
    if (typeof options === "function") {
      callback = options;
      options = {};
    }
    const opts = typeof options === "number" ? { family: options } : { ...(options || {}) };
    (base as any)(hostname, { ...opts, all: true }, (err: Error | null, addresses: any) => {
      if (err) return callback(err);
      const list: Array<{ address: string; family: number }> = Array.isArray(addresses) ? addresses : [];
      if (list.length === 0) return callback(new ReportUrlError(`${hostname} did not resolve`));
      const bad = list.find((a) => !isPublicAddress(a.address));
      if (bad) return callback(new ReportUrlError(`${hostname} resolves to a non-public address`));
      if (opts.all) return callback(null, list);
      callback(null, list[0].address, list[0].family);
    });
  };
  return guarded as unknown as LookupFn;
}

export interface FetchedReport {
  status: number;
  body: unknown;
}

/**
 * Fetches an already-validated report URL. Redirects are not followed (a
 * redirect would otherwise escape the allow-list), the destination address is
 * re-checked at connect time, and the body is size-capped. Environment proxies
 * are ignored so the connect-time address check always applies to the
 * destination host rather than to a proxy.
 */
export async function fetchReport(url: URL, lookup: LookupFn = dns.lookup): Promise<FetchedReport> {
  const agent = new https.Agent({ lookup: guardedLookup(lookup) as any });
  const resp = await axios.get(url.toString(), {
    timeout: FETCH_TIMEOUT_MS,
    maxRedirects: 0,
    maxContentLength: MAX_REPORT_BYTES,
    maxBodyLength: MAX_REPORT_BYTES,
    httpsAgent: agent,
    proxy: false,
  });
  return { status: resp.status, body: resp.data };
}
