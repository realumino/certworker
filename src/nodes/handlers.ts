import { normalizeDomainName } from "../acme/dns01";
import type { ApiKeyIdentity } from "../auth/api-key";
import { importEnvelopeSecret, decryptEnvelope } from "../crypto/envelope";
import type { PullDependencies } from "./deps";
import {
  findDomainByName,
  listDomainsForPull,
  type CertificateRow,
  type DomainRow,
} from "../store/d1";
import {
  certificatePrivateKeyKey,
  tryGetObjectBytes,
  tryGetObjectText,
} from "../store/r2";

/** Node-visible raw files (the admin surface adds `bundle`). */
export const PULL_FILES = ["cert", "chain", "fullchain", "key"] as const;
export type PullFile = (typeof PULL_FILES)[number];

/** Throttle window for `last_used_at` updates. */
export const LAST_USED_THROTTLE_MS = 60_000;

function pullJson(value: unknown, status = 200, headers: HeadersInit = {}): Response {
  return Response.json(value, {
    status,
    headers: { "Cache-Control": "no-store", ...headers },
  });
}

export function pullError(status: number, code: string, message?: string, headers?: HeadersInit): Response {
  return pullJson(message === undefined ? { error: code } : { error: code, message }, status, headers);
}

/** `"<serial>-<fingerprint>"` — quoted, so the manifest value can be sent back verbatim. */
export function certificateEtag(certificate: CertificateRow): string {
  return `"${certificate.serial}-${certificate.fingerprint_sha256}"`;
}

/** RFC 7232 If-None-Match comparison: `*`, comma lists, weak validators. */
export function ifNoneMatch(request: Request, etag: string): boolean {
  const header = request.headers.get("If-None-Match");
  if (header === null) return false;
  if (header.trim() === "*") return true;
  const bare = etag.replace(/"/g, "");
  return header.split(",").some((token) => {
    const candidate = token.trim().replace(/^W\//, "");
    return candidate === etag || candidate === bare;
  });
}

/** Parsed fail-closed: NULL ⇒ all domains, unparseable/non-string array ⇒ none. */
export function allowedDomains(key: ApiKeyIdentity["key"]): Set<string> | null {
  if (key.allowed_domains_json === null) return null;
  try {
    const parsed: unknown = JSON.parse(key.allowed_domains_json);
    if (Array.isArray(parsed) && parsed.every((name) => typeof name === "string")) {
      return new Set(parsed);
    }
  } catch {
    // fall through to deny
  }
  console.error(JSON.stringify({ event: "pull.invalid_allowed_domains", key_id: key.id }));
  return new Set();
}

export type ScopedDomain =
  | { response: null; domain: DomainRow }
  | { response: Response; domain: null };

/**
 * Normalize the requested name, resolve the row, and enforce the key's domain
 * scope. A non-null `response` is the error to return directly; an in-scope
 * denial is recorded as a 403 pull event (the row resolved, the pull failed).
 */
export async function resolveScopedDomain(
  context: PullContext,
  rawName: string,
): Promise<ScopedDomain> {
  const { deps, identity } = context;
  let name: string;
  try {
    name = normalizeDomainName(rawName);
  } catch {
    return { response: pullError(400, "invalid_domain_name", `${rawName} is not a valid domain name`), domain: null };
  }

  const domain = await findDomainByName(deps.db, name);
  if (!domain || domain.status === "deleted") {
    return { response: pullError(404, "not_found", "Domain not found"), domain: null };
  }

  const allowed = allowedDomains(identity.key);
  if (allowed !== null && !allowed.has(domain.name)) {
    recordPull(context, { domain, certificate: null, status: 403 });
    return {
      response: pullError(403, "forbidden_domain", "This API key is not scoped to the requested domain"),
      domain: null,
    };
  }
  return { response: null, domain };
}

export interface PullContext {
  deps: PullDependencies;
  identity: ApiKeyIdentity;
  request: Request;
}

/**
 * Queue the pull event and the throttled `last_used_at` bump off the response
 * path. The conditional UPDATE is atomic, so concurrent pulls cannot regress the
 * timestamp. Failures are logged, never surfaced to the node.
 */
export function recordPull(
  context: PullContext,
  outcome: { domain: DomainRow; certificate: CertificateRow | null; status: number },
): void {
  const { deps, identity, request } = context;
  const now = new Date();
  const staleBefore = new Date(now.getTime() - LAST_USED_THROTTLE_MS);
  deps.background((async () => {
    try {
      await deps.db.batch([
        deps.db.prepare(
          `INSERT INTO pull_events (id, api_key_id, domain_id, certificate_id, ip, user_agent, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        ).bind(
          crypto.randomUUID(),
          identity.key.id,
          outcome.domain.id,
          outcome.certificate?.id ?? null,
          request.headers.get("CF-Connecting-IP"),
          request.headers.get("User-Agent"),
          outcome.status,
          now.toISOString(),
        ),
        deps.db.prepare(
          `UPDATE api_keys SET last_used_at = ?
            WHERE id = ? AND status = 'active' AND (last_used_at IS NULL OR last_used_at <= ?)`,
        ).bind(now.toISOString(), identity.key.id, staleBefore.toISOString()),
      ]);
    } catch (error) {
      console.error(JSON.stringify({
        event: "pull.record_failed",
        key_id: identity.key.id,
        domain_id: outcome.domain.id,
        error: error instanceof Error ? error.message : String(error),
      }));
    }
  })());
}

export async function meHandler(deps: PullDependencies, identity: ApiKeyIdentity): Promise<Response> {
  const allowed = allowedDomains(identity.key);
  return pullJson({
    id: identity.key.id,
    label: identity.key.label,
    allowed_domains: allowed === null ? null : [...allowed],
  });
}

/** Cheap poll: scoped, non-deleted domains with current-certificate metadata (no PEMs). */
export async function listPullDomainsHandler(deps: PullDependencies, identity: ApiKeyIdentity): Promise<Response> {
  const allowed = allowedDomains(identity.key);
  const rows = await listDomainsForPull(deps.db);
  const scoped = allowed === null ? rows : rows.filter((row) => allowed.has(row.name));
  return pullJson({
    domains: scoped.map((row) => ({
      name: row.name,
      status: row.status,
      certificate: row.certificate_id === null ? null : {
        id: row.certificate_id,
        serial: row.certificate_serial,
        fingerprint_sha256: row.certificate_fingerprint_sha256,
        sans: parseSans(row.certificate_sans_json),
        not_before: row.certificate_not_before,
        not_after: row.certificate_not_after,
        etag: certificateEtagFromColumns(row.certificate_serial, row.certificate_fingerprint_sha256),
      },
    })),
  });
}

function certificateEtagFromColumns(serial: string | null, fingerprint: string | null): string | null {
  return serial === null || fingerprint === null ? null : `"${serial}-${fingerprint}"`;
}

/**
 * Certificate manifest: metadata plus all four PEMs (including the decrypted
 * private key), the shape the reference node agent consumes. Conditional
 * requests answered from the D1 row alone — no R2 reads, no decryption.
 */
export async function certificateManifestHandler(
  context: PullContext,
  domain: DomainRow,
): Promise<Response> {
  const certificate = await loadCurrentCertificate(context.deps, domain);
  if (!certificate) {
    recordPull(context, { domain, certificate: null, status: 404 });
    return pullError(404, "certificate_missing", `No current certificate for ${domain.name}`);
  }

  const etag = certificateEtag(certificate);
  const headers = { ETag: etag };
  if (ifNoneMatch(context.request, etag)) {
    recordPull(context, { domain, certificate, status: 304 });
    return new Response(null, { status: 304, headers: { "Cache-Control": "no-store", ...headers } });
  }

  let pems: Awaited<ReturnType<typeof loadCertificatePems>>;
  try {
    pems = await loadCertificatePems(context.deps, certificate);
  } catch (error) {
    if (error instanceof CertificateArtifactsMissingError) {
      recordPull(context, { domain, certificate, status: 404 });
      return pullError(404, "certificate_artifacts_missing", "The certificate's stored PEMs are unavailable");
    }
    throw error;
  }

  recordPull(context, { domain, certificate, status: 200 });
  return pullJson({
    domain: domain.name,
    sans: parseSans(certificate.sans_json),
    serial: certificate.serial,
    fingerprint_sha256: certificate.fingerprint_sha256,
    not_before: certificate.not_before,
    not_after: certificate.not_after,
    etag,
    cert_pem: pems.certPem,
    chain_pem: pems.chainPem,
    fullchain_pem: pems.fullchainPem,
    private_key_pem: pems.privateKeyPem,
  }, 200, headers);
}

/** Raw `cert|chain|fullchain|key` PEM, curl-friendly; `key` decrypts on the fly. */
export async function pullFileHandler(
  context: PullContext,
  domain: DomainRow,
  file: string,
): Promise<Response> {
  if (!PULL_FILES.includes(file as PullFile)) {
    return pullError(400, "invalid_file", `file must be one of: ${PULL_FILES.join(", ")}`);
  }

  const certificate = await loadCurrentCertificate(context.deps, domain);
  if (!certificate) {
    recordPull(context, { domain, certificate: null, status: 404 });
    return pullError(404, "certificate_missing", `No current certificate for ${domain.name}`);
  }

  const headers = { ETag: certificateEtag(certificate) };
  if (ifNoneMatch(context.request, headers.ETag)) {
    recordPull(context, { domain, certificate, status: 304 });
    return new Response(null, { status: 304, headers: { "Cache-Control": "no-store", ...headers } });
  }

  let pems: Awaited<ReturnType<typeof loadCertificatePems>>;
  try {
    pems = await loadCertificatePems(context.deps, certificate);
  } catch (error) {
    if (error instanceof CertificateArtifactsMissingError) {
      recordPull(context, { domain, certificate, status: 404 });
      return pullError(404, "certificate_artifacts_missing", "The certificate's stored PEMs are unavailable");
    }
    throw error;
  }

  const body = file === "cert" ? pems.certPem
    : file === "chain" ? pems.chainPem
    : file === "fullchain" ? pems.fullchainPem
    : pems.privateKeyPem;

  recordPull(context, { domain, certificate, status: 200 });
  return new Response(body, {
    status: 200,
    headers: {
      "Cache-Control": "no-store",
      ...headers,
      "Content-Type": "application/x-pem-file",
      "Content-Disposition": `attachment; filename="${pemFilename(domain.name, file)}"`,
    },
  });
}

function pemFilename(domainName: string, file: string): string {
  const safe = domainName.replace(/^\*\./, "wildcard.").replace(/[^a-z0-9._-]/g, "_");
  return `${safe}-${file === "key" ? "privkey" : file}.pem`;
}

function parseSans(value: string | null): string[] {
  if (value === null) return [];
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) && parsed.every((item) => typeof item === "string") ? parsed : [];
  } catch {
    return [];
  }
}

/** Current-certificate lookup for a resolved domain row. */
export async function loadCurrentCertificate(
  deps: PullDependencies,
  domain: DomainRow,
): Promise<CertificateRow | null> {
  return deps.db.prepare(
    "SELECT * FROM certificates WHERE domain_id = ? AND status = 'current'",
  ).bind(domain.id).first<CertificateRow>();
}

/** Typed marker for a R2 object that should exist but does not. */
export class CertificateArtifactsMissingError extends Error {
  constructor() {
    super("The certificate's stored PEMs are unavailable");
    this.name = "CertificateArtifactsMissing";
  }
}

/** Load the R2 PEMs and decrypt the private key; missing objects throw. */
export async function loadCertificatePems(
  deps: PullDependencies,
  certificate: CertificateRow,
): Promise<{ certPem: string; chainPem: string; fullchainPem: string; privateKeyPem: string }> {
  const prefix = certificate.r2_prefix;
  const [certPem, chainPem, fullchainPem] = await Promise.all([
    tryGetObjectText(deps.bucket, `${prefix}/cert.pem`),
    tryGetObjectText(deps.bucket, `${prefix}/chain.pem`),
    tryGetObjectText(deps.bucket, `${prefix}/fullchain.pem`),
  ]);
  if (certPem === null || chainPem === null || fullchainPem === null) {
    throw new CertificateArtifactsMissingError();
  }

  const keyPath = certificatePrivateKeyKey(prefix);
  const encrypted = await tryGetObjectBytes(deps.bucket, keyPath);
  if (encrypted === null) throw new CertificateArtifactsMissingError();
  const envelopeKey = await importEnvelopeSecret(deps.envelopeKey);
  const decrypted = await decryptEnvelope(encrypted, keyPath, envelopeKey);

  return { certPem, chainPem, fullchainPem, privateKeyPem: new TextDecoder().decode(decrypted) };
}
