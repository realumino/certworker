import { NonRetryableError } from "cloudflare:workflows";
import { AcmeError, AcmeProtocolError } from "../acme/errors";
import { issueErrorMessage } from "../issue/steps";
import {
  CertificateArtifactsMissingError,
  revokeStoredCertificate,
  type RevocationOutcome,
} from "../issue/revoke";
import { decryptEnvelope, importEnvelopeSecret } from "../crypto/envelope";
import {
  getCertificate,
  getDomain,
  listCertificates,
  type CertificateRow,
  type CertificateStatus,
  type CertificateWithDomainRow,
} from "../store/d1";
import { certificatePrivateKeyKey, tryGetObjectBytes, tryGetObjectText } from "../store/r2";
import type { AdminDependencies } from "./deps";
import { recordAudit } from "./audit";
import { errorResponse, jsonResponse, parseJsonArray, parsePagination } from "./http";

const CERTIFICATE_STATUSES: readonly CertificateStatus[] = ["current", "superseded", "revoked"];
const DOWNLOAD_FILES = ["cert", "chain", "fullchain", "key", "bundle"] as const;
type DownloadFile = (typeof DOWNLOAD_FILES)[number];

export async function listCertificatesHandler(deps: AdminDependencies, request: Request): Promise<Response> {
  const url = new URL(request.url);
  const pagination = parsePagination(url);
  if (pagination instanceof Response) return pagination;

  const statusParam = url.searchParams.get("status");
  if (statusParam !== null && !CERTIFICATE_STATUSES.includes(statusParam as CertificateStatus)) {
    return errorResponse(400, "invalid_status", `status must be one of: ${CERTIFICATE_STATUSES.join(", ")}`);
  }

  const rows = await listCertificates(deps.db, {
    domainId: url.searchParams.get("domain_id") ?? undefined,
    status: (statusParam as CertificateStatus) ?? undefined,
    ...pagination,
  });
  return jsonResponse(rows.map(certificateJson));
}

export async function getCertificateHandler(
  deps: AdminDependencies,
  _request: Request,
  params: Record<string, string>,
): Promise<Response> {
  const row = await getCertificate(deps.db, params.id);
  if (!row) return errorResponse(404, "not_found", "Certificate not found");
  const domain = await getDomain(deps.db, row.domain_id);
  return jsonResponse(certificateJson({ ...row, domain_name: domain?.name ?? "" }));
}

export async function revokeCertificateHandler(
  deps: AdminDependencies,
  _request: Request,
  params: Record<string, string>,
): Promise<Response> {
  const row = await getCertificate(deps.db, params.id);
  if (!row) return errorResponse(404, "not_found", "Certificate not found");

  let outcome: RevocationOutcome;
  try {
    outcome = await revokeStoredCertificate(deps, row);
  } catch (error) {
    if (error instanceof CertificateArtifactsMissingError) {
      return errorResponse(409, "certificate_artifacts_missing", error.message);
    }
    if (error instanceof AcmeError || error instanceof AcmeProtocolError || error instanceof NonRetryableError) {
      return errorResponse(502, "upstream_error", issueErrorMessage(error));
    }
    throw error;
  }

  await recordAudit(deps, "certificate.revoke", row.id, {
    domain_id: row.domain_id,
    serial: row.serial,
    ca_status: outcome.status,
    purged: outcome.purged,
  });

  const updated = (await getCertificate(deps.db, row.id)) ?? row;
  return jsonResponse({ certificate: certificateJson(updated), ...outcome });
}

export async function downloadCertificateHandler(
  deps: AdminDependencies,
  request: Request,
  params: Record<string, string>,
): Promise<Response> {
  const url = new URL(request.url);
  const file = url.searchParams.get("file") ?? "";
  if (!DOWNLOAD_FILES.includes(file as DownloadFile)) {
    return errorResponse(400, "invalid_file", `file must be one of: ${DOWNLOAD_FILES.join(", ")}`);
  }

  const row = await getCertificate(deps.db, params.id);
  if (!row) return errorResponse(404, "not_found", "Certificate not found");
  if (row.purged_at !== null) return artifactsMissing();

  let body: string;
  if (file === "key") {
    const key = await loadPrivateKeyPem(deps, row);
    if (key === null) return artifactsMissing();
    body = key;
  } else if (file === "bundle") {
    // Combined PEM (fullchain then private key), as consumed by HAProxy-style configs.
    const fullchain = await tryGetObjectText(deps.bucket, `${row.r2_prefix}/fullchain.pem`);
    if (fullchain === null) return artifactsMissing();
    const key = await loadPrivateKeyPem(deps, row);
    if (key === null) return artifactsMissing();
    body = joinPem(fullchain, key);
  } else {
    const text = await tryGetObjectText(deps.bucket, `${row.r2_prefix}/${file}.pem`);
    if (text === null) return artifactsMissing();
    body = text;
  }

  const domain = await getDomain(deps.db, row.domain_id);
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "application/x-pem-file",
      "Content-Disposition": `attachment; filename="${pemFilename(domain?.name ?? row.id, file)}"`,
      "Cache-Control": "no-store",
    },
  });
}

/** Decrypt the certificate's private key; null when the encrypted object is gone. */
async function loadPrivateKeyPem(deps: AdminDependencies, row: CertificateRow): Promise<string | null> {
  const keyPath = certificatePrivateKeyKey(row.r2_prefix);
  const encrypted = await tryGetObjectBytes(deps.bucket, keyPath);
  if (encrypted === null) return null;
  const envelopeKey = await importEnvelopeSecret(deps.envelopeKey);
  const plaintext = await decryptEnvelope(encrypted, keyPath, envelopeKey);
  return new TextDecoder().decode(plaintext);
}

function joinPem(first: string, second: string): string {
  const left = first.endsWith("\n") ? first : `${first}\n`;
  const right = second.endsWith("\n") ? second : `${second}\n`;
  return left + right;
}

function pemFilename(domainName: string, file: string): string {
  const safe = domainName.replace(/^\*\./, "wildcard.").replace(/[^a-z0-9._-]/g, "_");
  return `${safe}-${file === "key" ? "privkey" : file}.pem`;
}

function artifactsMissing(): Response {
  return errorResponse(404, "certificate_artifacts_missing", "The certificate's stored PEMs are unavailable");
}

function certificateJson(row: CertificateRow & Partial<CertificateWithDomainRow>): Record<string, unknown> {
  return {
    id: row.id,
    domain_id: row.domain_id,
    ...(row.domain_name !== undefined ? { domain_name: row.domain_name } : {}),
    env: row.env,
    serial: row.serial,
    fingerprint_sha256: row.fingerprint_sha256,
    sans: parseJsonArray(row.sans_json),
    not_before: row.not_before,
    not_after: row.not_after,
    issued_at: row.issued_at,
    r2_prefix: row.r2_prefix,
    status: row.status,
    purged_at: row.purged_at,
    created_at: row.created_at,
  };
}
