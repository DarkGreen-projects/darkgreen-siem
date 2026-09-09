export type IocKind = "ip" | "url" | "domain";

export type IocHit = {
  kind: IocKind;
  value: string;
  vtUrl: string;
};

const IPV4_RE =
  /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const URL_RE = /\bhttps?:\/\/[^\s<>"'`]+/gi;
const DOMAIN_RE =
  /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|app|cloud|info|biz|edu|gov|mil|co|uk|it|de|fr|es|nl|eu|local|example|test|invalid)\b/gi;

const PRIVATE_OR_DOCS = new Set([
  "127.0.0.1",
  "0.0.0.0",
  "255.255.255.255",
]);

function isLikelyPrivateIpv4(ip: string): boolean {
  if (PRIVATE_OR_DOCS.has(ip)) return true;
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return false;
  if (p[0] === 10) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  // Still allow RFC5737 docs ranges (used in demo) for VT lookup
  return false;
}

function vtIp(ip: string): string {
  return `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`;
}

function vtDomain(domain: string): string {
  return `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`;
}

/** VirusTotal GUI expects URL-safe base64 without padding. */
export function vtUrlLink(url: string): string {
  const b64 = btoa(unescape(encodeURIComponent(url)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `https://www.virustotal.com/gui/url/${b64}`;
}

export function isIpv4(value: string): boolean {
  return /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/.test(
    value.trim()
  );
}

function pushUnique(out: IocHit[], hit: IocHit, seen: Set<string>) {
  const key = `${hit.kind}:${hit.value.toLowerCase()}`;
  if (seen.has(key)) return;
  seen.add(key);
  out.push(hit);
}

function collectFromText(text: string, out: IocHit[], seen: Set<string>) {
  if (!text) return;

  for (const m of text.matchAll(URL_RE)) {
    let url = m[0].replace(/[),.;]+$/, "");
    if (url.length > 8) {
      pushUnique(out, { kind: "url", value: url, vtUrl: vtUrlLink(url) }, seen);
    }
  }

  for (const m of text.matchAll(IPV4_RE)) {
    const ip = m[0];
    if (isLikelyPrivateIpv4(ip)) continue;
    pushUnique(out, { kind: "ip", value: ip, vtUrl: vtIp(ip) }, seen);
  }

  for (const m of text.matchAll(DOMAIN_RE)) {
    const domain = m[0].toLowerCase();
    if (domain.includes("virustotal.com")) continue;
    if (domain.endsWith(".local") || domain.endsWith(".example") || domain.endsWith(".test")) {
      continue;
    }
    pushUnique(out, { kind: "domain", value: domain, vtUrl: vtDomain(domain) }, seen);
  }
}

function walkEvidence(value: unknown, out: IocHit[], seen: Set<string>, depth = 0) {
  if (depth > 6 || value == null) return;
  if (typeof value === "string") {
    if (isIpv4(value) && !isLikelyPrivateIpv4(value)) {
      pushUnique(out, { kind: "ip", value, vtUrl: vtIp(value) }, seen);
    } else {
      collectFromText(value, out, seen);
    }
    return;
  }
  if (typeof value === "number" || typeof value === "boolean") return;
  if (Array.isArray(value)) {
    for (const item of value) walkEvidence(item, out, seen, depth + 1);
    return;
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    for (const [k, v] of Object.entries(obj)) {
      if (k === "src_ip" || k === "dst_ip" || k === "key") {
        if (typeof v === "string" && isIpv4(v) && !isLikelyPrivateIpv4(v)) {
          pushUnique(out, { kind: "ip", value: v, vtUrl: vtIp(v) }, seen);
        } else if (typeof v === "string") {
          collectFromText(v, out, seen);
        }
      } else {
        walkEvidence(v, out, seen, depth + 1);
      }
    }
  }
}

/** Extract IOCs from alert fields + evidence for VirusTotal GUI links. */
export function extractIocsFromAlert(alert: {
  title?: string;
  description?: string;
  threat_brief?: string | null;
  evidence?: Record<string, unknown> | null;
}): IocHit[] {
  const out: IocHit[] = [];
  const seen = new Set<string>();
  collectFromText(alert.title || "", out, seen);
  collectFromText(alert.description || "", out, seen);
  collectFromText(alert.threat_brief || "", out, seen);
  walkEvidence(alert.evidence || {}, out, seen);
  return out.slice(0, 20);
}

export function iocForIp(ip: string | null | undefined): IocHit | null {
  if (!ip || !isIpv4(ip) || isLikelyPrivateIpv4(ip)) return null;
  return { kind: "ip", value: ip, vtUrl: vtIp(ip) };
}
