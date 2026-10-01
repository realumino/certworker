import { deleteTxtRecord } from "../dns/cloudflare";
import {
  listStaleChallengeRecords,
  listUnpurgedCertificates,
  markChallengeRecordDeleted,
  markCertificatePurged,
} from "../store/d1";
import { deletePrefix } from "../store/r2";

export interface SweeperDependencies {
  db: D1Database;
  bucket: R2Bucket;
  dnsApiToken: string;
  fetcher: typeof fetch;
  now: () => Date;
}

export interface CertificateSweepResult {
  purged: number;
  failed: number;
}

export interface ChallengeSweepResult {
  deleted: number;
  failed: number;
}

/** Aggregated over both passes; sub-results share a `failed` key, so the
 * combined result uses distinct names. */
export interface SweepResult {
  certificatesPurged: number;
  certificateFailures: number;
  challengesDeleted: number;
  challengeFailures: number;
}

/** Challenge TXT records younger than this are the live workflow's business. */
export const STALE_CHALLENGE_MS = 24 * 60 * 60 * 1000;

/**
 * Daily-cron cleanup for state the normal pipeline could not finish:
 * superseded/revoked certificate prefixes whose R2 objects still exist
 * (`purge-previous` and revoke purge are best-effort) and `_acme-challenge`
 * records a crashed workflow never deleted. Every item is attempted; one
 * failure never blocks the rest or throws.
 */
export async function sweep(deps: SweeperDependencies): Promise<SweepResult> {
  const certificates = await sweepUnpurgedCertificates(deps);
  const challenges = await sweepStaleChallengeRecords(deps);
  return {
    certificatesPurged: certificates.purged,
    certificateFailures: certificates.failed,
    challengesDeleted: challenges.deleted,
    challengeFailures: challenges.failed,
  };
}

export async function sweepUnpurgedCertificates(deps: SweeperDependencies): Promise<CertificateSweepResult> {
  const rows = await listUnpurgedCertificates(deps.db);
  let purged = 0;
  let failed = 0;

  for (const certificate of rows) {
    try {
      await deletePrefix(deps.bucket, certificate.r2_prefix);
      await markCertificatePurged(deps.db, certificate.id);
      purged += 1;
    } catch (error) {
      failed += 1;
      console.warn(JSON.stringify({
        event: "sweeper.certificate_failed",
        certificateId: certificate.id,
        r2Prefix: certificate.r2_prefix,
        error: errorMessage(error),
      }));
    }
  }

  return { purged, failed };
}

export async function sweepStaleChallengeRecords(deps: SweeperDependencies): Promise<ChallengeSweepResult> {
  const cutoff = new Date(deps.now().getTime() - STALE_CHALLENGE_MS).toISOString();
  const rows = await listStaleChallengeRecords(deps.db, cutoff);
  let deleted = 0;
  let failed = 0;

  for (const record of rows) {
    try {
      // The Cloudflare API answers 404 for an already-gone record; that counts as deleted.
      await deleteTxtRecord({
        apiToken: deps.dnsApiToken,
        zoneId: record.zone_id,
        recordId: record.cf_record_id,
        fetch: deps.fetcher,
      });
      await markChallengeRecordDeleted(deps.db, record.id);
      deleted += 1;
    } catch (error) {
      failed += 1;
      console.warn(JSON.stringify({
        event: "sweeper.challenge_failed",
        recordId: record.id,
        cfRecordId: record.cf_record_id,
        error: errorMessage(error),
      }));
    }
  }

  return { deleted, failed };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
