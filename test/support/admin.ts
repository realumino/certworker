import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createScriptedFetch, jsonResponse } from "./fake-fetch";
import { ACCESS_JWT_HEADER } from "../../src/auth/access";
import { sha256Hex } from "../../src/crypto/keys";
import { encryptEnvelope, importEnvelopeSecret } from "../../src/crypto/envelope";
import { certificatePrefix, certificatePrivateKeyKey } from "../../src/store/r2";
import type { ApiKeyRow, ApiKeyStatus, CertificateRow, CertificateStatus, PullEventRow } from "../../src/store/d1";
import type { IssueWorkflowCreator } from "../../src/issue/trigger";
import type { AcmeEnvironment } from "../../src/issue/types";
import type { AdminOptions } from "../../src/admin/deps";

export interface TestAccess {
  teamDomain: string;
  aud: string;
  email: string;
  jwks: { keys: Array<Record<string, unknown>> };
  signToken: (tokenOptions?: {
    email?: string;
    issuer?: string;
    audience?: string;
    expiresIn?: string | number;
  }) => Promise<string>;
}

/** Standard AdminOptions for router tests: explicit Access config + scripted JWKS fetch. */
export function adminOptions(
  access: TestAccess,
  fetcher: typeof fetch,
  issuance?: IssueWorkflowCreator,
): AdminOptions {
  return {
    access: { teamDomain: access.teamDomain, aud: access.aud, devEmail: null },
    fetcher,
    ...(issuance ? { issuance } : {}),
  };
}

/**
 * Builds an RS256 test identity whose JWKS the Worker can be pointed at via
 * `AdminOptions.access`. Verification behavior (iss/aud/expiry/signature) is
 * exercised through `signToken` options.
 */
export async function createTestAccess(
  options: { teamDomain?: string; aud?: string; email?: string; kid?: string } = {},
): Promise<TestAccess> {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(publicKey);
  const kid = options.kid ?? "test-access-key";
  const teamDomain = options.teamDomain ?? "https://team-test.cloudflareaccess.com";
  const aud = options.aud ?? "aud-test";
  const email = options.email ?? "admin@example.com";

  return {
    teamDomain,
    aud,
    email,
    jwks: { keys: [{ ...publicJwk, kid, alg: "RS256", use: "sig" }] },
    async signToken(tokenOptions = {}) {
      return new SignJWT({ email: tokenOptions.email ?? email })
        .setProtectedHeader({ alg: "RS256", kid })
        .setIssuer(tokenOptions.issuer ?? teamDomain)
        .setAudience(tokenOptions.audience ?? aud)
        .setIssuedAt()
        .setExpirationTime(tokenOptions.expiresIn ?? "5m")
        .sign(privateKey);
    },
  };
}

/** Scripted outbound fetch that always answers with the test JWKS. */
export function jwksFetcher(access: TestAccess) {
  return createScriptedFetch(() => jsonResponse(access.jwks));
}

/** Same-origin JSON mutation (or plain read) with the Access JWT header — the SPA's shape. */
export function accessRequest(path: string, token: string, init: RequestInit = {}): Request {
  const headers: Record<string, string> = {
    "Origin": "https://certworker.example.org",
    "Sec-Fetch-Site": "same-origin",
    // Every admin mutation is JSON-only, including body-less POST/DELETE.
    "Content-Type": "application/json",
  };
  if (token !== "") headers[ACCESS_JWT_HEADER] = token;

  return new Request(`https://certworker.example.org${path}`, {
    ...init,
    headers: { ...headers, ...(init.headers as Record<string, string> | undefined) },
  });
}

export async function seedApiKey(
  db: D1Database,
  options: {
    id?: string;
    label?: string;
    status?: ApiKeyStatus;
    allowedDomains?: string[] | null;
    /** When given, `key_hash` is the SHA-256 of this secret (builds a usable token). */
    secret?: string;
  } = {},
): Promise<ApiKeyRow> {
  const id = options.id ?? crypto.randomUUID();
  const now = new Date().toISOString();
  const row: ApiKeyRow = {
    id,
    label: options.label ?? "node-1",
    key_hash: options.secret === undefined ? `hash-${id}` : await sha256Hex(options.secret),
    key_hint: `cw_${id}…1234`,
    allowed_domains_json: options.allowedDomains === undefined ? null : JSON.stringify(options.allowedDomains),
    status: options.status ?? "active",
    created_at: now,
    last_used_at: null,
    revoked_at: options.status === "revoked" ? now : null,
  };
  await db.prepare(
    `INSERT INTO api_keys (id, label, key_hash, key_hint, allowed_domains_json, status, created_at, last_used_at, revoked_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    row.id,
    row.label,
    row.key_hash,
    row.key_hint,
    row.allowed_domains_json,
    row.status,
    row.created_at,
    row.last_used_at,
    row.revoked_at,
  ).run();
  return row;
}

/**
 * Insert a certificate row and, unless skipped, its R2 artifacts (three PEM
 * texts plus an AES-GCM encrypted private key whose AAD is the R2 object path).
 */
export async function seedCertificate(
  db: D1Database,
  bucket: R2Bucket,
  domainId: string,
  envelopeKey: string,
  options: {
    domainName?: string;
    id?: string;
    certificateEnv?: AcmeEnvironment;
    status?: CertificateStatus;
    purgedAt?: string | null;
    notAfter?: string;
    notBefore?: string;
    serial?: string;
    sans?: string[];
    storeArtifacts?: boolean;
    privateKeyPem?: string;
    /** Overrides the default placeholder leaf PEM (needed by revoke/parse flows). */
    certPem?: string;
  } = {},
): Promise<CertificateRow> {
  const certificateId = options.id ?? crypto.randomUUID();
  const domainName = options.domainName ?? `cert-${certificateId.slice(0, 8)}.example.com`;
  const r2Prefix = certificatePrefix(domainName, certificateId);
  const now = new Date().toISOString();
  const row: CertificateRow = {
    id: certificateId,
    domain_id: domainId,
    env: options.certificateEnv ?? "staging",
    serial: options.serial ?? "0011aa22bb33cc44dd55ee66ff778899",
    fingerprint_sha256: crypto.randomUUID().replaceAll("-", ""),
    sans_json: JSON.stringify(options.sans ?? ["example.com", "*.example.com"]),
    not_before: options.notBefore ?? now,
    not_after: options.notAfter ?? new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(),
    issued_at: now,
    r2_prefix: r2Prefix,
    status: options.status ?? "current",
    purged_at: options.purgedAt ?? null,
    created_at: now,
  };
  await db.prepare(
    `INSERT INTO certificates (
       id, domain_id, env, serial, fingerprint_sha256, sans_json, not_before, not_after,
       issued_at, r2_prefix, status, purged_at, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    row.id,
    row.domain_id,
    row.env,
    row.serial,
    row.fingerprint_sha256,
    row.sans_json,
    row.not_before,
    row.not_after,
    row.issued_at,
    row.r2_prefix,
    row.status,
    row.purged_at,
    row.created_at,
  ).run();

  if (options.storeArtifacts !== false) {
    await Promise.all([
      bucket.put(`${r2Prefix}/cert.pem`, options.certPem ?? `LEAF PEM for ${certificateId}\n`),
      bucket.put(`${r2Prefix}/chain.pem`, `CHAIN PEM for ${certificateId}\n`),
      bucket.put(`${r2Prefix}/fullchain.pem`, `FULLCHAIN PEM for ${certificateId}\n`),
    ]);
    const privateKey = options.privateKeyPem ?? `PRIVATE KEY for ${certificateId}\n`;
    const keyPath = certificatePrivateKeyKey(r2Prefix);
    const encrypted = await encryptEnvelope(
      new TextEncoder().encode(privateKey),
      keyPath,
      await importEnvelopeSecret(envelopeKey),
    );
    await bucket.put(keyPath, encrypted);
  }

  return row;
}

export async function seedPullEvent(
  db: D1Database,
  apiKeyId: string,
  domainId: string,
  options: { certificateId?: string | null; status?: number } = {},
): Promise<PullEventRow> {
  const row: PullEventRow = {
    id: crypto.randomUUID(),
    api_key_id: apiKeyId,
    domain_id: domainId,
    certificate_id: options.certificateId ?? null,
    ip: "203.0.113.10",
    user_agent: "certworker-agent/1.0",
    status: options.status ?? 200,
    created_at: new Date().toISOString(),
  };
  await db.prepare(
    `INSERT INTO pull_events (id, api_key_id, domain_id, certificate_id, ip, user_agent, status, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    row.id,
    row.api_key_id,
    row.domain_id,
    row.certificate_id,
    row.ip,
    row.user_agent,
    row.status,
    row.created_at,
  ).run();
  return row;
}

