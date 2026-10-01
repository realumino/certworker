import { NonRetryableError } from "cloudflare:workflows";
import { normalizeDomainName } from "../acme/dns01";
import { AcmeError, AcmeProtocolError } from "../acme/errors";
import { issueErrorMessage } from "../issue/steps";
import { CertificateArtifactsMissingError, revokeStoredCertificate } from "../issue/revoke";
import {
  CloudflareApiError,
  findZoneId,
  getZone,
  listZones,
  type CloudflareZone,
} from "../dns/cloudflare";
import {
  ActiveIssueRunError,
  IssueDomainNotActiveError,
  IssueDomainNotFoundError,
  startIssueRun,
} from "../issue/trigger";
import {
  createDomain,
  DomainNameConflictError,
  findActiveIssueRun,
  findDomainByName,
  getDomain,
  getCurrentCertificate,
  listDomains,
  softDeleteDomain,
  updateDomainSettings,
  type DomainRow,
  type DomainStatus,
  type DomainWithCertificateRow,
} from "../store/d1";
import { recordAudit } from "./audit";
import type { AdminDependencies } from "./deps";
import {
  errorResponse,
  jsonResponse,
  optionalBoolean,
  optionalIntegerInRange,
  optionalString,
  parseJsonArray,
  parseJsonBody,
  parsePagination,
  rejectUnknownFields,
  requireString,
} from "./http";

const DOMAIN_STATUSES: readonly DomainStatus[] = ["active", "paused", "deleted"];
const RENEW_BEFORE_MIN = 1;
const RENEW_BEFORE_MAX = 90;

export async function listZonesHandler(deps: AdminDependencies): Promise<Response> {
  try {
    const zones = await listZones({ apiToken: deps.dnsApiToken, fetch: deps.fetcher });
    return jsonResponse(zones.map(({ id, name, status }) => ({ id, name, status: status ?? null })));
  } catch (error) {
    if (error instanceof CloudflareApiError) return errorResponse(502, "upstream_error", error.message);
    throw error;
  }
}

export async function listDomainsHandler(deps: AdminDependencies, request: Request): Promise<Response> {
  const url = new URL(request.url);
  const pagination = parsePagination(url);
  if (pagination instanceof Response) return pagination;

  const statusParam = url.searchParams.get("status");
  if (statusParam !== null && !DOMAIN_STATUSES.includes(statusParam as DomainStatus)) {
    return errorResponse(400, "invalid_status", `status must be one of: ${DOMAIN_STATUSES.join(", ")}`);
  }

  const rows = await listDomains(deps.db, { status: (statusParam as DomainStatus) ?? undefined, ...pagination });
  return jsonResponse(rows.map(domainJson));
}

export async function getDomainHandler(
  deps: AdminDependencies,
  _request: Request,
  params: Record<string, string>,
): Promise<Response> {
  const row = await loadDomainWithCertificate(deps, params.id);
  if (!row) return errorResponse(404, "not_found", "Domain not found");
  return jsonResponse(domainJson(row));
}

export async function createDomainHandler(deps: AdminDependencies, request: Request): Promise<Response> {
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;

  const unknown = rejectUnknownFields(body, ["name", "include_wildcard", "renew_before_days", "zone_id"]);
  if (unknown) return unknown;

  const name = requireString(body, "name");
  if (name instanceof Response) return name;

  let normalized: string;
  try {
    normalized = normalizeDomainName(name);
  } catch {
    return errorResponse(400, "invalid_domain_name", `${name} is not a valid DNS name for issuance`);
  }
  const wildcardOnly = normalized.startsWith("*.");

  const includeWildcardValue = optionalBoolean(body, "include_wildcard");
  if (includeWildcardValue instanceof Response) return includeWildcardValue;
  // A wildcard-only row issues exactly the wildcard SAN; the toggle does not apply.
  const includeWildcard = wildcardOnly ? false : includeWildcardValue ?? true;

  const renewBeforeValue = optionalIntegerInRange(body, "renew_before_days", RENEW_BEFORE_MIN, RENEW_BEFORE_MAX);
  if (renewBeforeValue instanceof Response) return renewBeforeValue;

  const zoneIdInput = optionalString(body, "zone_id");
  if (zoneIdInput instanceof Response) return zoneIdInput;

  let zoneId: string;
  if (zoneIdInput !== undefined) {
    const resolved = await resolveProvidedZone(deps, zoneIdInput, normalized);
    if (resolved instanceof Response) return resolved;
    zoneId = resolved;
  } else {
    try {
      zoneId = await findZoneId({ apiToken: deps.dnsApiToken, domain: normalized, fetch: deps.fetcher });
    } catch (error) {
      if (error instanceof CloudflareApiError) return zoneLookupResponse(error);
      throw error;
    }
  }

  const existing = await findDomainByName(deps.db, normalized);
  if (existing) {
    return errorResponse(
      409,
      "domain_exists",
      `A domain row already exists for ${normalized} (status: ${existing.status})`,
    );
  }
  const overlap = await findWildcardOverlap(deps.db, normalized, includeWildcard);
  if (overlap) {
    return errorResponse(
      409,
      "wildcard_overlap",
      `${overlap.name} already issues the wildcard SAN for ${normalized.replace(/^\*\./, "")}`,
    );
  }

  const domainId = crypto.randomUUID();
  try {
    await createDomain(deps.db, {
      id: domainId,
      name: normalized,
      zone_id: zoneId,
      include_wildcard: includeWildcard ? 1 : 0,
      renew_before_days: renewBeforeValue ?? 30,
    });
  } catch (error) {
    if (error instanceof DomainNameConflictError) {
      return errorResponse(409, "domain_exists", `A domain row already exists for ${normalized}`);
    }
    throw error;
  }
  await recordAudit(deps, "domain.create", domainId, {
    name: normalized,
    zone_id: zoneId,
    include_wildcard: includeWildcard,
  });

  const row = await loadDomainWithCertificate(deps, domainId);
  if (!row) throw new Error(`Domain ${domainId} is missing right after creation`);
  return jsonResponse(domainJson(row), 201);
}

export async function updateDomainHandler(
  deps: AdminDependencies,
  request: Request,
  params: Record<string, string>,
): Promise<Response> {
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;

  const unknown = rejectUnknownFields(body, ["include_wildcard", "renew_before_days", "status"]);
  if (unknown) return unknown;

  const domain = await getDomain(deps.db, params.id);
  if (!domain || domain.status === "deleted") return errorResponse(404, "not_found", "Domain not found");

  const includeWildcardValue = optionalBoolean(body, "include_wildcard");
  if (includeWildcardValue instanceof Response) return includeWildcardValue;
  const renewBeforeValue = optionalIntegerInRange(body, "renew_before_days", RENEW_BEFORE_MIN, RENEW_BEFORE_MAX);
  if (renewBeforeValue instanceof Response) return renewBeforeValue;
  const statusValue = optionalString(body, "status");
  if (statusValue instanceof Response) return statusValue;

  if (includeWildcardValue === undefined && renewBeforeValue === undefined && statusValue === undefined) {
    return errorResponse(
      400,
      "invalid_request",
      "At least one of include_wildcard, renew_before_days, status is required",
    );
  }
  if (statusValue !== undefined && !["active", "paused"].includes(statusValue)) {
    return errorResponse(400, "invalid_status", "status must be one of: active, paused");
  }
  if (domain.name.startsWith("*.") && includeWildcardValue !== undefined) {
    return errorResponse(400, "invalid_request", "The wildcard toggle does not apply to wildcard-only domain rows");
  }
  if (includeWildcardValue === true && domain.include_wildcard !== 1) {
    const overlap = await findWildcardOverlap(deps.db, domain.name, true);
    if (overlap) {
      return errorResponse(409, "wildcard_overlap", `${overlap.name} already issues the wildcard SAN for ${domain.name}`);
    }
  }

  const finalWildcard = includeWildcardValue !== undefined ? includeWildcardValue : domain.include_wildcard === 1;
  const finalRenewBefore = renewBeforeValue ?? domain.renew_before_days;
  const finalStatus: DomainStatus = statusValue !== undefined ? (statusValue as DomainStatus) : domain.status;

  await updateDomainSettings(deps.db, domain.id, {
    include_wildcard: finalWildcard ? 1 : 0,
    renew_before_days: finalRenewBefore,
    status: finalStatus,
  });
  await recordAudit(deps, "domain.update", domain.id, {
    changes: {
      ...(includeWildcardValue !== undefined
        ? { include_wildcard: { from: domain.include_wildcard === 1, to: finalWildcard } }
        : {}),
      ...(renewBeforeValue !== undefined
        ? { renew_before_days: { from: domain.renew_before_days, to: finalRenewBefore } }
        : {}),
      ...(statusValue !== undefined ? { status: { from: domain.status, to: finalStatus } } : {}),
    },
  });

  const row = await loadDomainWithCertificate(deps, domain.id);
  if (!row) throw new Error(`Domain ${domain.id} is missing after its update`);
  return jsonResponse(domainJson(row));
}

export async function deleteDomainHandler(
  deps: AdminDependencies,
  _request: Request,
  params: Record<string, string>,
): Promise<Response> {
  const domain = await getDomain(deps.db, params.id);
  if (!domain) return errorResponse(404, "not_found", "Domain not found");

  if (domain.status !== "deleted") {
    const activeRun = await findActiveIssueRun(deps.db, domain.id);
    if (activeRun) {
      return errorResponse(409, "run_in_progress", `${domain.name} has an active issue run; retry after it finishes`);
    }

    // M7: deletion revokes the current certificate first (account key + purge),
    // then soft-deletes the row so history and audit survive.
    const current = await getCurrentCertificate(deps.db, domain.id);
    let revoke: "none" | "revoked" | "already_revoked" | "artifacts_missing" = "none";
    if (current) {
      try {
        revoke = (await revokeStoredCertificate(deps, current)).status;
      } catch (error) {
        if (error instanceof CertificateArtifactsMissingError) {
          // Nothing revocable remains (PEMs already purged); keep the deletion.
          revoke = "artifacts_missing";
        } else if (
          error instanceof AcmeError ||
          error instanceof AcmeProtocolError ||
          error instanceof NonRetryableError
        ) {
          return errorResponse(
            502,
            "upstream_error",
            `Revocation failed for ${domain.name}: ${issueErrorMessage(error)}`,
          );
        } else {
          throw error;
        }
      }
    }

    await softDeleteDomain(deps.db, domain.id);
    await recordAudit(deps, "domain.delete", domain.id, { name: domain.name, revoke });
  }

  const row = await loadDomainWithCertificate(deps, domain.id);
  if (!row) throw new Error(`Domain ${domain.id} is missing after its deletion`);
  return jsonResponse(domainJson(row));
}

export async function issueDomainHandler(
  deps: AdminDependencies,
  _request: Request,
  params: Record<string, string>,
): Promise<Response> {
  const domain = await getDomain(deps.db, params.id);
  if (!domain || domain.status === "deleted") return errorResponse(404, "not_found", "Domain not found");
  if (domain.status !== "active") {
    return errorResponse(409, "domain_not_active", `Domain ${domain.name} is ${domain.status}, not active`);
  }

  let started: Awaited<ReturnType<typeof startIssueRun>>;
  try {
    started = await startIssueRun(deps.db, deps.issuance, domain.id, { trigger: "manual" });
  } catch (error) {
    if (error instanceof IssueDomainNotFoundError) return errorResponse(404, "not_found", "Domain not found");
    if (error instanceof IssueDomainNotActiveError) {
      return errorResponse(409, "domain_not_active", `Domain ${domain.name} is ${domain.status}, not active`);
    }
    if (error instanceof ActiveIssueRunError) {
      return errorResponse(409, "run_in_progress", `${domain.name} already has an active issue run`);
    }
    return errorResponse(
      502,
      "upstream_error",
      `Workflow creation failed for ${domain.name}; the run was recorded as failed`,
    );
  }

  await recordAudit(deps, "domain.issue", domain.id, {
    run_id: started.runId,
    workflow_id: started.workflowId,
  });
  return jsonResponse({ run_id: started.runId, workflow_id: started.workflowId, status: "queued" }, 202);
}

async function resolveProvidedZone(
  deps: AdminDependencies,
  zoneId: string,
  normalized: string,
): Promise<string | Response> {
  let zone: CloudflareZone;
  try {
    zone = await getZone({ apiToken: deps.dnsApiToken, zoneId, fetch: deps.fetcher });
  } catch (error) {
    if (!(error instanceof CloudflareApiError)) throw error;
    if (error.status === 404) {
      return errorResponse(400, "zone_not_found", `Zone ${zoneId} was not found with the configured DNS API token`);
    }
    return errorResponse(502, "upstream_error", error.message);
  }

  if (zone.status !== undefined && zone.status !== "active") {
    return errorResponse(400, "zone_not_active", `Zone ${zone.name} is ${zone.status}, not active`);
  }

  const baseName = normalized.replace(/^\*\./, "");
  const zoneName = zone.name.toLowerCase();
  if (baseName !== zoneName && !baseName.endsWith(`.${zoneName}`)) {
    return errorResponse(400, "zone_mismatch", `${normalized} is not inside zone ${zone.name}`);
  }
  return zone.id;
}

function zoneLookupResponse(error: CloudflareApiError): Response {
  if (error.status === 404) return errorResponse(400, "zone_not_found", error.message);
  return errorResponse(502, "upstream_error", error.message);
}

/**
 * An apex row with include_wildcard and a wildcard-only row for the same base
 * name would publish different TXT values at the same `_acme-challenge` name;
 * creating that pair is rejected here.
 */
async function findWildcardOverlap(
  db: D1Database,
  normalized: string,
  includeWildcard: boolean,
): Promise<DomainRow | null> {
  const baseName = normalized.replace(/^\*\./, "");
  const otherName = normalized.startsWith("*.") ? baseName : `*.${baseName}`;
  const other = await findDomainByName(db, otherName);
  if (!other || other.status === "deleted") return null;
  if (normalized.startsWith("*.")) return other.include_wildcard === 1 ? other : null;
  return includeWildcard ? other : null;
}

async function loadDomainWithCertificate(
  deps: AdminDependencies,
  id: string,
): Promise<DomainWithCertificateRow | null> {
  const domain = await getDomain(deps.db, id);
  if (!domain) return null;
  const certificate = await getCurrentCertificate(deps.db, id);
  return {
    ...domain,
    certificate_id: certificate?.id ?? null,
    certificate_env: certificate?.env ?? null,
    certificate_serial: certificate?.serial ?? null,
    certificate_sans_json: certificate?.sans_json ?? null,
    certificate_not_before: certificate?.not_before ?? null,
    certificate_not_after: certificate?.not_after ?? null,
    certificate_fingerprint_sha256: certificate?.fingerprint_sha256 ?? null,
  };
}

function domainJson(row: DomainWithCertificateRow): Record<string, unknown> {
  return {
    id: row.id,
    name: row.name,
    zone_id: row.zone_id,
    include_wildcard: row.include_wildcard === 1,
    key_type: row.key_type,
    renew_before_days: row.renew_before_days,
    preferred_chain: row.preferred_chain,
    status: row.status,
    last_error: row.last_error,
    created_at: row.created_at,
    updated_at: row.updated_at,
    current_certificate: row.certificate_id === null ? null : {
      id: row.certificate_id,
      env: row.certificate_env,
      serial: row.certificate_serial,
      sans: parseJsonArray(row.certificate_sans_json),
      not_after: row.certificate_not_after,
    },
  };
}
