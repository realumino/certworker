import { NonRetryableError } from "cloudflare:workflows";
import { AcmeClient, type AcmeIdentifier, type AcmeOrder } from "../acme/client";
import { AcmeError, AcmeProtocolError, isRateLimited } from "../acme/errors";
import { dns01RecordName, dns01Value, normalizeDomainName, waitForTxtPropagation } from "../acme/dns01";
import { CloudflareApiError, createTxtRecord, deleteTxtRecord } from "../dns/cloudflare";
import { parseCertificate, splitCertificateChain } from "../crypto/certificate";
import { buildCsr } from "../crypto/csr";
import { b64uDecode, b64uEncode } from "../crypto/base64url";
import { decryptEnvelope, decodeEnvelopeSecret, encryptEnvelope, importEnvelopeKey } from "../crypto/envelope";
import { exportPrivateKeyPem, importPrivateKeyPem } from "../crypto/pem";
import { exportPublicJwk, generateEcP256KeyPair, jwkThumbprint } from "../crypto/keys";
import {
  activateCertificate,
  findPendingChallengeRecord,
  getAcmeAccount,
  getCertificate,
  getCurrentCertificate,
  getDomain,
  insertChallengeRecord,
  listPendingChallengeRecords,
  markCertificatePurged,
  markChallengeRecordDeleted,
  saveAcmeAccount,
  type CertificateRow,
  type DomainRow,
} from "../store/d1";
import {
  accountPrivateKeyKey,
  certificatePrefix,
  certificatePrivateKeyKey,
  deletePrefix,
  getAcmeAccountMetadata,
  getObjectBytes,
  putAcmeAccount,
  putCertificateArtifacts,
  putCertificatePrivateKey,
  type AcmeAccountMetadata,
} from "../store/r2";
import type { AcmeEnvironment } from "./types";

const STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory";
const PRODUCTION_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory";

export interface IssueTimings {
  dnsTimeoutMs: number;
  dnsPollIntervalMs: number;
  dnsSettleMs: number;
  dnsRequestTimeoutMs: number;
  acmeTimeoutMs: number;
  acmePollIntervalMs: number;
  acmeRequestTimeoutMs: number;
}

export interface IssueDependencies {
  db: D1Database;
  bucket: R2Bucket;
  directoryUrl: string;
  envelopeKey: string;
  dnsApiToken: string;
  fetcher: typeof fetch;
  timings: IssueTimings;
}

export interface LoadedIssue {
  domain: DomainRow;
  identifiers: AcmeIdentifier[];
  previousCertificate: CertificateRow | null;
}

export interface AcmeAccountState {
  environment: AcmeEnvironment;
  accountUrl: string;
  thumbprint: string;
}

export interface NewOrderState {
  orderUrl: string;
  authorizations: string[];
}

export interface AuthorizationWorkItem {
  authorizationUrl: string;
  identifier: string;
  status: "valid" | "pending";
  challengeUrl?: string;
  challengeStatus?: string;
}

export interface PublishedChallenges {
  authorizations: AuthorizationWorkItem[];
  targets: Array<{ name: string; values: string[] }>;
}

export interface LeafKeyState {
  certificateId: string;
  r2Prefix: string;
  csrB64u: string;
  publicJwk: Awaited<ReturnType<typeof exportPublicJwk>>;
}

export interface StoredCertificate {
  certificateId: string;
  r2Prefix: string;
  serial: string;
  fingerprintSha256: string;
  sans: string[];
  notBefore: string;
  notAfter: string;
}

const DEFAULT_TIMINGS: IssueTimings = {
  dnsTimeoutMs: 5 * 60_000,
  dnsPollIntervalMs: 5_000,
  dnsSettleMs: 10_000,
  dnsRequestTimeoutMs: 10_000,
  acmeTimeoutMs: 5 * 60_000,
  acmePollIntervalMs: 3_000,
  acmeRequestTimeoutMs: 30_000,
};

export function createIssueDependencies(
  env: Pick<Env, "DB" | "CERTS" | "ACME_DIRECTORY" | "ENVELOPE_KEY" | "CF_DNS_API_TOKEN">,
  options: { fetcher?: typeof fetch; timings?: Partial<IssueTimings> } = {},
): IssueDependencies {
  return {
    db: env.DB,
    bucket: env.CERTS,
    directoryUrl: env.ACME_DIRECTORY,
    envelopeKey: env.ENVELOPE_KEY,
    dnsApiToken: env.CF_DNS_API_TOKEN,
    fetcher: options.fetcher ?? globalThis.fetch,
    timings: { ...DEFAULT_TIMINGS, ...options.timings },
  };
}

export async function loadIssue(
  deps: IssueDependencies,
  runId: string,
  domainId: string,
): Promise<LoadedIssue> {
  const domain = await getDomain(deps.db, domainId);
  if (!domain) throw new NonRetryableError(JSON.stringify({ error: "domain_not_found", domainId }));
  if (domain.status !== "active") {
    throw new NonRetryableError(JSON.stringify({ error: "domain_not_active", domainId, status: domain.status }));
  }
  if (!/^[A-Za-z0-9_-]+$/.test(runId)) throw new NonRetryableError("Issue run id is not safe for R2 object paths");

  let normalized: string;
  try {
    normalized = normalizeDomainName(domain.name);
  } catch (error) {
    throw new NonRetryableError(issueErrorMessage(error));
  }

  const identifiers: AcmeIdentifier[] = normalized.startsWith("*.")
    ? [{ type: "dns", value: normalized }]
    : [
        { type: "dns", value: normalized },
        ...(domain.include_wildcard === 1 ? [{ type: "dns" as const, value: `*.${normalized}` }] : []),
      ];

  return {
    domain,
    identifiers,
    previousCertificate: await getCurrentCertificate(deps.db, domainId),
  };
}

export async function ensureAcmeAccount(deps: IssueDependencies): Promise<AcmeAccountState> {
  const environment = acmeEnvironment(deps.directoryUrl);
  const existing = await getAcmeAccount(deps.db, environment);
  if (existing) {
    if (existing.directory_url !== deps.directoryUrl) {
      throw new NonRetryableError(`ACME account for ${environment} belongs to a different directory`);
    }
    const context = await loadAcmeAccount(deps, environment);
    return {
      environment,
      accountUrl: context.accountUrl,
      thumbprint: context.thumbprint,
    };
  }

  const keyPair = await generateEcP256KeyPair();
  const publicJwk = await exportPublicJwk(keyPair.publicKey);
  const client = new AcmeClient({
    directoryUrl: deps.directoryUrl,
    accountKey: keyPair,
    fetch: deps.fetcher,
    requestTimeoutMs: deps.timings.acmeRequestTimeoutMs,
  });

  let accountUrl: string;
  try {
    accountUrl = await client.ensureAccount();
  } catch (error) {
    throwPermanentAcmeError(error);
  }

  const privateKeyKey = accountPrivateKeyKey(environment);
  const privateKeyPem = await exportPrivateKeyPem(keyPair.privateKey);
  const encryptedPrivateKey = await encryptEnvelope(
    new TextEncoder().encode(privateKeyPem),
    privateKeyKey,
    await getEnvelopeKey(deps),
  );
  const metadata: AcmeAccountMetadata = {
    version: 1,
    directoryUrl: deps.directoryUrl,
    accountUrl,
    publicJwk,
  };

  await putAcmeAccount(deps.bucket, environment, metadata, encryptedPrivateKey);
  await saveAcmeAccount(deps.db, {
    id: crypto.randomUUID(),
    env: environment,
    directory_url: deps.directoryUrl,
    account_url: accountUrl,
    key_r2_key: privateKeyKey,
  });

  const saved = await loadAcmeAccount(deps, environment);
  return { environment, accountUrl: saved.accountUrl, thumbprint: saved.thumbprint };
}

export async function createOrder(
  deps: IssueDependencies,
  account: AcmeAccountState,
  identifiers: AcmeIdentifier[],
): Promise<NewOrderState> {
  const { client } = await loadAcmeAccount(deps, account.environment);
  try {
    const order = await client.newOrder(identifiers);
    if (!sameIdentifiers(order.identifiers, identifiers)) {
      throw new NonRetryableError("ACME order identifiers did not match the requested SANs");
    }
    return { orderUrl: order.url, authorizations: order.authorizations };
  } catch (error) {
    throwPermanentAcmeError(error);
  }
}

export async function publishTxtChallenges(
  deps: IssueDependencies,
  runId: string,
  domain: DomainRow,
  account: AcmeAccountState,
  authorizationUrls: string[],
): Promise<PublishedChallenges> {
  const { client, thumbprint } = await loadAcmeAccount(deps, account.environment);
  const authorizations: AuthorizationWorkItem[] = [];
  const targets = new Map<string, Set<string>>();

  for (const authorizationUrl of [...new Set(authorizationUrls)]) {
    let authorization;
    try {
      authorization = await client.getAuthorization(authorizationUrl);
    } catch (error) {
      throwPermanentAcmeError(error);
    }

    const identifier = authorization.identifier.value;
    if (authorization.status === "valid") {
      authorizations.push({ authorizationUrl, identifier, status: "valid" });
      continue;
    }
    if (authorization.status === "invalid") {
      throw new NonRetryableError(problemMessage(authorization.error, `Authorization for ${identifier} is invalid`));
    }

    const challenge = authorization.challenges.find(({ type }) => type === "dns-01");
    if (!challenge) {
      throw new NonRetryableError(`ACME returned no DNS-01 challenge for ${identifier}`);
    }
    if (challenge.status === "invalid") {
      throw new NonRetryableError(problemMessage(challenge.error, `DNS-01 challenge for ${identifier} is invalid`));
    }
    if (challenge.status === "valid") {
      authorizations.push({
        authorizationUrl,
        identifier,
        status: "pending",
        challengeUrl: challenge.url,
        challengeStatus: "valid",
      });
      continue;
    }
    if (!challenge.token) throw new NonRetryableError(`DNS-01 challenge for ${identifier} is missing its token`);

    const value = await dns01Value(challenge.token, thumbprint);
    const name = dns01RecordName(identifier);
    const existingRecord = await findPendingChallengeRecord(deps.db, runId, name, value);
    let recordId = existingRecord?.cf_record_id;
    if (!recordId) {
      try {
        recordId = await createTxtRecord({
          apiToken: deps.dnsApiToken,
          zoneId: domain.zone_id,
          name,
          value,
          ttl: 60,
          fetch: deps.fetcher,
          requestTimeoutMs: deps.timings.dnsRequestTimeoutMs,
        });
      } catch (error) {
        throwPermanentCloudflareError(error);
      }
      await insertChallengeRecord(deps.db, {
        id: crypto.randomUUID(),
        run_id: runId,
        zone_id: domain.zone_id,
        cf_record_id: recordId,
        name,
        value,
      });
    }

    const values = targets.get(name) ?? new Set<string>();
    values.add(value);
    targets.set(name, values);

    authorizations.push({
      authorizationUrl,
      identifier,
      status: "pending",
      challengeUrl: challenge.url,
      challengeStatus: challenge.status,
    });
  }

  return {
    authorizations,
    targets: [...targets].map(([name, values]) => ({ name, values: [...values] })),
  };
}

export async function waitForPropagation(
  deps: IssueDependencies,
  published: PublishedChallenges,
): Promise<void> {
  if (published.targets.length === 0) return;
  try {
    await waitForTxtPropagation(published.targets, {
      fetch: deps.fetcher,
      timeoutMs: deps.timings.dnsTimeoutMs,
      pollIntervalMs: deps.timings.dnsPollIntervalMs,
      settleMs: deps.timings.dnsSettleMs,
      requestTimeoutMs: deps.timings.dnsRequestTimeoutMs,
    });
  } catch (error) {
    throw new NonRetryableError(issueErrorMessage(error));
  }
}

export async function acceptChallenges(
  deps: IssueDependencies,
  account: AcmeAccountState,
  published: PublishedChallenges,
): Promise<void> {
  const pending = published.authorizations.filter(
    (item): item is AuthorizationWorkItem & { challengeUrl: string; challengeStatus: string } =>
      item.challengeStatus === "pending" && typeof item.challengeUrl === "string",
  );
  if (pending.length === 0) return;

  const { client } = await loadAcmeAccount(deps, account.environment);
  for (const authorization of pending) {
    try {
      await client.acceptChallenge(authorization.challengeUrl);
    } catch (error) {
      throwPermanentAcmeError(error);
    }
  }
}

export async function awaitAuthorizations(
  deps: IssueDependencies,
  account: AcmeAccountState,
  published: PublishedChallenges,
): Promise<void> {
  const pending = published.authorizations.filter(({ status }) => status !== "valid");
  if (pending.length === 0) return;

  const { client } = await loadAcmeAccount(deps, account.environment);
  for (const authorization of pending) {
    try {
      await client.waitForAuthorizationValid(authorization.authorizationUrl, {
        timeoutMs: deps.timings.acmeTimeoutMs,
        pollIntervalMs: deps.timings.acmePollIntervalMs,
      });
    } catch (error) {
      throwPermanentAcmeError(error);
    }
  }
}

export async function createLeafKeyAndCsr(
  deps: IssueDependencies,
  runId: string,
  domain: DomainRow,
  identifiers: AcmeIdentifier[],
): Promise<LeafKeyState> {
  const certificateId = runId;
  const r2Prefix = certificatePrefix(domain.name, certificateId);
  const keyPair = await generateEcP256KeyPair();
  const publicJwk = await exportPublicJwk(keyPair.publicKey);
  const csr = await buildCsr(keyPair, identifiers.map(({ value }) => value));
  const key = await exportPrivateKeyPem(keyPair.privateKey);
  const privateKeyKey = certificatePrivateKeyKey(r2Prefix);
  const encryptedKey = await encryptEnvelope(
    new TextEncoder().encode(key),
    privateKeyKey,
    await getEnvelopeKey(deps),
  );
  await putCertificatePrivateKey(deps.bucket, r2Prefix, encryptedKey);

  return {
    certificateId,
    r2Prefix,
    csrB64u: b64uEncode(csr.der),
    publicJwk,
  };
}

export async function finalizeAndStore(
  deps: IssueDependencies,
  domain: DomainRow,
  identifiers: AcmeIdentifier[],
  account: AcmeAccountState,
  order: NewOrderState,
  leaf: LeafKeyState,
): Promise<StoredCertificate> {
  const existing = await getCertificate(deps.db, leaf.certificateId);
  if (existing) {
    if (existing.domain_id !== domain.id) throw new Error(`Certificate ${leaf.certificateId} belongs to another domain`);
    return storedCertificateFromRow(existing);
  }

  const { client } = await loadAcmeAccount(deps, account.environment);
  let validOrder: AcmeOrder;
  try {
    const readyOrder = await client.waitForOrderReady(order.orderUrl, {
      timeoutMs: deps.timings.acmeTimeoutMs,
      pollIntervalMs: deps.timings.acmePollIntervalMs,
    });
    await client.finalizeOrder(readyOrder.finalize, b64uDecode(leaf.csrB64u), order.orderUrl);
    validOrder = await client.waitForOrderValid(order.orderUrl, {
      timeoutMs: deps.timings.acmeTimeoutMs,
      pollIntervalMs: deps.timings.acmePollIntervalMs,
    });
    if (!validOrder.certificate) throw new NonRetryableError("Valid ACME order is missing its certificate URL");
  } catch (error) {
    throwPermanentAcmeError(error);
  }

  let downloadedChain: string;
  try {
    downloadedChain = await client.downloadCertificate(validOrder.certificate);
  } catch (error) {
    throwPermanentAcmeError(error);
  }

  const chain = splitCertificateChain(downloadedChain);
  const parsed = await parseCertificate(chain.leafPem);
  if (!sameNames(parsed.sans, identifiers.map(({ value }) => value))) {
    throw new NonRetryableError(
      `Issued certificate SAN mismatch: expected [${identifiers.map(({ value }) => value).join(", ")}], received [${parsed.sans.join(", ")}]`,
    );
  }
  if (parsed.publicKeyJwk.x !== leaf.publicJwk.x || parsed.publicKeyJwk.y !== leaf.publicJwk.y) {
    throw new NonRetryableError("Issued certificate public key does not match the generated CSR key");
  }

  await assertPrivateKeyMatchesCertificate(deps, leaf, parsed.publicKeyJwk, parsed.fingerprintSha256);

  const issuedAt = new Date().toISOString();
  const metadata = {
    certificate_id: leaf.certificateId,
    domain: domain.name,
    environment: account.environment,
    sans: parsed.sans,
    serial: parsed.serial,
    fingerprint_sha256: parsed.fingerprintSha256,
    not_before: parsed.notBefore,
    not_after: parsed.notAfter,
    issued_at: issuedAt,
    key_type: "ecdsa_p256",
  };
  const metaJson = `${JSON.stringify(metadata, null, 2)}\n`;

  await putCertificateArtifacts(deps.bucket, leaf.r2Prefix, {
    certPem: chain.leafPem,
    chainPem: chain.chainPem,
    fullchainPem: chain.fullchainPem,
    metaJson,
  });

  const certificate: CertificateRow = {
    id: leaf.certificateId,
    domain_id: domain.id,
    env: account.environment,
    serial: parsed.serial,
    fingerprint_sha256: parsed.fingerprintSha256,
    sans_json: JSON.stringify(parsed.sans),
    not_before: parsed.notBefore,
    not_after: parsed.notAfter,
    issued_at: issuedAt,
    r2_prefix: leaf.r2Prefix,
    status: "current",
    purged_at: null,
    created_at: issuedAt,
  };
  await activateCertificate(deps.db, certificate);

  return {
    certificateId: certificate.id,
    r2Prefix: certificate.r2_prefix,
    serial: certificate.serial,
    fingerprintSha256: certificate.fingerprint_sha256,
    sans: parsed.sans,
    notBefore: certificate.not_before,
    notAfter: certificate.not_after,
  };
}

export async function purgePreviousCertificate(
  deps: IssueDependencies,
  previous: CertificateRow | null,
): Promise<{ purged: boolean }> {
  if (!previous) return { purged: false };
  await deletePrefix(deps.bucket, previous.r2_prefix);
  await markCertificatePurged(deps.db, previous.id);
  return { purged: true };
}

export async function cleanupFailedArtifacts(
  deps: IssueDependencies,
  domainName: string,
  certificateId: string,
): Promise<{ deleted: boolean }> {
  // Once D1 has a certificate row, the prefix is committed history and must stay intact.
  if (await getCertificate(deps.db, certificateId)) return { deleted: false };
  await deletePrefix(deps.bucket, certificatePrefix(domainName, certificateId));
  return { deleted: true };
}

export async function cleanupTxtRecords(
  deps: IssueDependencies,
  runId: string,
): Promise<{ deleted: number }> {
  const records = await listPendingChallengeRecords(deps.db, runId);
  const failures: string[] = [];
  let deleted = 0;

  for (const record of records) {
    try {
      await deleteTxtRecord({
        apiToken: deps.dnsApiToken,
        zoneId: record.zone_id,
        recordId: record.cf_record_id,
        fetch: deps.fetcher,
        requestTimeoutMs: deps.timings.dnsRequestTimeoutMs,
      });
      await markChallengeRecordDeleted(deps.db, record.id);
      deleted += 1;
    } catch (error) {
      failures.push(`${record.cf_record_id}: ${issueErrorMessage(error)}`);
    }
  }

  if (failures.length > 0) throw new Error(`Could not remove all ACME TXT records: ${failures.join("; ")}`);
  return { deleted };
}

export function issueErrorMessage(error: unknown): string {
  if (error instanceof AcmeError) return error.rawBody ?? JSON.stringify(error.problem);
  if (error instanceof CloudflareApiError) {
    return JSON.stringify({ status: error.status, errors: error.errors, message: error.message });
  }
  if (error instanceof AggregateError) {
    return [...error.errors].map(issueErrorMessage).join("; ");
  }
  return error instanceof Error ? error.message : String(error);
}

async function loadAcmeAccount(
  deps: IssueDependencies,
  environment: AcmeEnvironment,
): Promise<{ client: AcmeClient; accountUrl: string; thumbprint: string }> {
  const account = await getAcmeAccount(deps.db, environment);
  if (!account) throw new Error(`ACME account for ${environment} has not been initialized`);
  if (account.directory_url !== deps.directoryUrl) {
    throw new NonRetryableError(`ACME account for ${environment} belongs to a different directory`);
  }

  const metadata = await getAcmeAccountMetadata(deps.bucket, environment);
  if (metadata.directoryUrl !== account.directory_url || metadata.accountUrl !== account.account_url) {
    throw new TypeError(`ACME account metadata for ${environment} does not match D1`);
  }
  if (account.key_r2_key !== accountPrivateKeyKey(environment)) {
    throw new TypeError(`ACME account private-key path for ${environment} is invalid`);
  }

  const encryptedKey = await getObjectBytes(deps.bucket, account.key_r2_key);
  const privateKeyPem = new TextDecoder().decode(
    await decryptEnvelope(encryptedKey, account.key_r2_key, await getEnvelopeKey(deps)),
  );
  const privateKey = await importPrivateKeyPem(privateKeyPem);
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    metadata.publicJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const client = new AcmeClient({
    directoryUrl: deps.directoryUrl,
    accountKey: { privateKey, publicKey },
    kid: account.account_url,
    fetch: deps.fetcher,
    requestTimeoutMs: deps.timings.acmeRequestTimeoutMs,
  });
  return {
    client,
    accountUrl: account.account_url,
    thumbprint: await jwkThumbprint(metadata.publicJwk),
  };
}

async function getEnvelopeKey(deps: IssueDependencies): Promise<CryptoKey> {
  try {
    return await importEnvelopeKey(decodeEnvelopeSecret(deps.envelopeKey));
  } catch (error) {
    throw new NonRetryableError(`ENVELOPE_KEY is invalid: ${issueErrorMessage(error)}`);
  }
}

async function assertPrivateKeyMatchesCertificate(
  deps: IssueDependencies,
  leaf: LeafKeyState,
  publicJwk: LeafKeyState["publicJwk"],
  fingerprint: string,
): Promise<void> {
  const privateKeyBytes = await getObjectBytes(deps.bucket, certificatePrivateKeyKey(leaf.r2Prefix));
  const privateKeyPem = new TextDecoder().decode(
    await decryptEnvelope(privateKeyBytes, certificatePrivateKeyKey(leaf.r2Prefix), await getEnvelopeKey(deps)),
  );
  const privateKey = await importPrivateKeyPem(privateKeyPem);
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    publicJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const proof = new TextEncoder().encode(`${leaf.certificateId}:${fingerprint}`);
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, proof);
  if (!(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signature, proof))) {
    throw new NonRetryableError("Encrypted private key does not match the issued certificate");
  }
}

function storedCertificateFromRow(row: CertificateRow): StoredCertificate {
  let sans: string[];
  try {
    const parsed: unknown = JSON.parse(row.sans_json);
    if (!Array.isArray(parsed) || !parsed.every((name) => typeof name === "string")) throw new TypeError();
    sans = parsed;
  } catch {
    throw new TypeError(`Certificate ${row.id} has invalid SAN metadata`);
  }
  return {
    certificateId: row.id,
    r2Prefix: row.r2_prefix,
    serial: row.serial,
    fingerprintSha256: row.fingerprint_sha256,
    sans,
    notBefore: row.not_before,
    notAfter: row.not_after,
  };
}

function acmeEnvironment(directoryUrl: string): AcmeEnvironment {
  if (directoryUrl === STAGING_DIRECTORY) return "staging";
  if (directoryUrl === PRODUCTION_DIRECTORY) return "production";
  throw new NonRetryableError(`Unsupported ACME directory: ${directoryUrl}`);
}

function throwPermanentAcmeError(error: unknown): never {
  if (
    error instanceof AcmeError &&
    !isRetryableRateLimit(error) &&
    (error.responseStatus === 200 || (error.responseStatus >= 400 && error.responseStatus < 500))
  ) {
    throw new NonRetryableError(issueErrorMessage(error));
  }
  if (error instanceof AcmeProtocolError) throw new NonRetryableError(error.message);
  throw error;
}

function isRetryableRateLimit(error: AcmeError): boolean {
  return isRateLimited(error);
}

function throwPermanentCloudflareError(error: unknown): never {
  if (
    error instanceof CloudflareApiError &&
    error.status !== 429 &&
    (error.status < 500 || error.status >= 600)
  ) {
    throw new NonRetryableError(issueErrorMessage(error));
  }
  throw error;
}

function problemMessage(problem: Record<string, unknown> | undefined, fallback: string): string {
  return problem ? JSON.stringify(problem) : fallback;
}

function sameIdentifiers(actual: AcmeIdentifier[], expected: AcmeIdentifier[]): boolean {
  return sameNames(actual.map(({ value }) => value), expected.map(({ value }) => value));
}

function sameNames(actual: string[], expected: string[]): boolean {
  const actualNames = new Set(actual);
  const expectedNames = new Set(expected);
  return actualNames.size === expectedNames.size && expected.some((name) => !actualNames.has(name)) === false;
}
