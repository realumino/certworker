import { isAlreadyRevoked } from "../acme/errors";
import { pemToDer } from "../crypto/pem";
import { createIssueDependencies, issueErrorMessage, loadAcmeAccount } from "./steps";
import type { CertificateRow } from "../store/d1";
import { markCertificatePurged, markCertificateRevoked } from "../store/d1";
import { deletePrefix, tryGetObjectText } from "../store/r2";

export interface RevocationDependencies {
  db: D1Database;
  bucket: R2Bucket;
  directoryUrl: string;
  envelopeKey: string;
  /** Carried so the assembled `IssueDependencies` is complete; revocation itself never uses DNS. */
  dnsApiToken: string;
  fetcher: typeof fetch;
}

export class CertificateArtifactsMissingError extends Error {
  constructor() {
    super("The certificate's stored PEMs are unavailable, so it cannot be revoked");
    this.name = "CertificateArtifactsMissingError";
  }
}

export interface RevocationOutcome {
  /** What the CA answered for the revocation request itself. */
  status: "revoked" | "already_revoked";
  /** false means the sweeper still has to remove the R2 prefix. */
  purged: boolean;
}

/**
 * ACME-revoke a stored certificate with its issuing account key, then retire it
 * in D1 and delete its R2 artifacts. The order keeps any crash recoverable:
 * ask the CA first (the account key is the authority), flip D1 to `revoked`
 * next, then purge R2 — a crash mid-purge leaves a row the sweeper picks up
 * (`purged_at IS NULL AND status != 'current'`). Idempotent end to end:
 *
 * - `alreadyRevoked` answers from the CA count as success (RFC 8555 Section 7.6).
 * - a row already `revoked` in D1 skips the CA call and only re-runs the purge.
 */
export async function revokeStoredCertificate(
  deps: RevocationDependencies,
  certificate: CertificateRow,
): Promise<RevocationOutcome> {
  if (certificate.status === "revoked") {
    return { status: "already_revoked", purged: await purgeArtifacts(deps, certificate) };
  }

  if (certificate.purged_at !== null) throw new CertificateArtifactsMissingError();
  const certPem = await tryGetObjectText(deps.bucket, `${certificate.r2_prefix}/cert.pem`);
  if (certPem === null) throw new CertificateArtifactsMissingError();

  const issueDeps = createIssueDependencies(
    {
      DB: deps.db,
      CERTS: deps.bucket,
      ACME_DIRECTORY: deps.directoryUrl,
      ENVELOPE_KEY: deps.envelopeKey,
      CF_DNS_API_TOKEN: deps.dnsApiToken,
    },
    { fetcher: deps.fetcher },
  );
  const { client } = await loadAcmeAccount(issueDeps, certificate.env);

  let caStatus: RevocationOutcome["status"] = "revoked";
  try {
    await client.revokeCertificate(pemToDer(certPem, "CERTIFICATE"));
  } catch (error) {
    if (!isAlreadyRevoked(error)) throw error;
    caStatus = "already_revoked";
  }

  await markCertificateRevoked(deps.db, certificate.id);
  return { status: caStatus, purged: await purgeArtifacts(deps, certificate) };
}

/** Delete the stored PEMs and set `purged_at`; failures are logged, never thrown. */
async function purgeArtifacts(deps: RevocationDependencies, certificate: CertificateRow): Promise<boolean> {
  try {
    await deletePrefix(deps.bucket, certificate.r2_prefix);
    await markCertificatePurged(deps.db, certificate.id);
    return true;
  } catch (error) {
    console.warn(JSON.stringify({
      event: "certificate.purge_failed",
      certificateId: certificate.id,
      error: issueErrorMessage(error),
    }));
    return false;
  }
}
