import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
  activateCertificate,
  ActiveIssueRunError,
  createIssueRun,
  finishIssueRun,
  getAcmeAccount,
  getCertificate,
  getCurrentCertificate,
  getIssueRun,
  insertChallengeRecord,
  listPendingChallengeRecords,
  markCertificatePurged,
  markChallengeRecordDeleted,
  recordRunPhase,
  saveAcmeAccount,
  type CertificateRow,
} from "../src/store/d1";
import { seedDomain } from "./support/fixtures";

describe("D1 persistence", () => {
  it("records run phases and finalizes a run idempotently", async () => {
    const domain = await seedDomain(env.DB);
    const runId = crypto.randomUUID();
    await createIssueRun(env.DB, {
      id: runId,
      domain_id: domain.id,
      workflow_id: `manual-${runId}`,
      trigger: "manual",
    });

    await recordRunPhase(env.DB, runId, "load");
    await recordRunPhase(env.DB, runId, "new-order");
    const running = await getIssueRun(env.DB, runId);
    expect(running).toMatchObject({ status: "running", phase: "new-order" });
    expect(JSON.parse(running?.steps_json ?? "[]")).toHaveLength(2);

    await finishIssueRun(env.DB, runId, domain.id, { status: "succeeded" });
    await finishIssueRun(env.DB, runId, domain.id, { status: "succeeded" });
    expect(await getIssueRun(env.DB, runId)).toMatchObject({
      status: "succeeded",
      phase: "complete",
      error: null,
    });
  });

  it("uses the active-run partial unique index to serialize issuance", async () => {
    const domain = await seedDomain(env.DB);
    const firstRun = crypto.randomUUID();
    await createIssueRun(env.DB, {
      id: firstRun,
      domain_id: domain.id,
      workflow_id: `manual-${firstRun}`,
      trigger: "manual",
    });

    const secondRun = crypto.randomUUID();
    await expect(createIssueRun(env.DB, {
      id: secondRun,
      domain_id: domain.id,
      workflow_id: `manual-${secondRun}`,
      trigger: "manual",
    })).rejects.toBeInstanceOf(ActiveIssueRunError);

    await finishIssueRun(env.DB, firstRun, domain.id, { status: "failed", error: "test failure" });
    await createIssueRun(env.DB, {
      id: secondRun,
      domain_id: domain.id,
      workflow_id: `manual-${secondRun}`,
      trigger: "manual",
    });
    expect(await getIssueRun(env.DB, secondRun)).toMatchObject({ status: "queued" });
  });

  it("atomically flips the current certificate and marks purged history", async () => {
    const domain = await seedDomain(env.DB);
    const first = certificate(domain.id, crypto.randomUUID(), "a".repeat(64));
    const second = certificate(domain.id, crypto.randomUUID(), "b".repeat(64));

    await activateCertificate(env.DB, first);
    expect(await getCurrentCertificate(env.DB, domain.id)).toMatchObject({ id: first.id, status: "current" });

    await activateCertificate(env.DB, second);
    expect(await getCertificate(env.DB, first.id)).toMatchObject({ status: "superseded" });
    expect(await getCurrentCertificate(env.DB, domain.id)).toMatchObject({ id: second.id, status: "current" });

    await markCertificatePurged(env.DB, first.id);
    expect(await getCertificate(env.DB, first.id)).toMatchObject({ status: "superseded", purged_at: expect.any(String) });

    await expect(activateCertificate(env.DB, {
      ...second,
      fingerprint_sha256: "c".repeat(64),
    })).rejects.toThrow("already in use");
  });

  it("persists one ACME account per environment and tracks TXT cleanup", async () => {
    const domain = await seedDomain(env.DB);
    const runId = crypto.randomUUID();
    await createIssueRun(env.DB, {
      id: runId,
      domain_id: domain.id,
      workflow_id: `manual-${runId}`,
      trigger: "manual",
    });

    await saveAcmeAccount(env.DB, {
      id: crypto.randomUUID(),
      env: "staging",
      directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory",
      account_url: "https://acme.example/account/1",
      key_r2_key: "acme/staging/account-key.pem.enc",
    });
    expect(await getAcmeAccount(env.DB, "staging")).toMatchObject({ account_url: "https://acme.example/account/1" });

    await insertChallengeRecord(env.DB, {
      id: crypto.randomUUID(),
      run_id: runId,
      zone_id: domain.zone_id,
      cf_record_id: "cf-record-1",
      name: `_acme-challenge.${domain.name}`,
      value: "challenge-value",
    });
    const [record] = await listPendingChallengeRecords(env.DB, runId);
    expect(record).toMatchObject({ cf_record_id: "cf-record-1", deleted_at: null });
    await markChallengeRecordDeleted(env.DB, record.id);
    expect(await listPendingChallengeRecords(env.DB, runId)).toEqual([]);
  });
});

function certificate(domainId: string, id: string, fingerprint: string): CertificateRow {
  const now = new Date().toISOString();
  return {
    id,
    domain_id: domainId,
    env: "staging",
    serial: id.replaceAll("-", ""),
    fingerprint_sha256: fingerprint,
    sans_json: '["example.com"]',
    not_before: now,
    not_after: new Date(Date.now() + 90 * 24 * 60 * 60_000).toISOString(),
    issued_at: now,
    r2_prefix: `certs/example.com/${id}`,
    status: "current",
    purged_at: null,
    created_at: now,
  };
}
