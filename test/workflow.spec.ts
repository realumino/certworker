import { introspectWorkflowInstance } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { seedDomain, seedIssueRun } from "./support/fixtures";
import { getIssueRun } from "../src/store/d1";
import type { IssuePayload } from "../src/issue/types";

describe("CertificateWorkflow orchestration", () => {
  it("runs the durable steps and finalizes the D1 run", async () => {
    const domain = await seedDomain(env.DB);
    const { runId, workflowId } = await seedIssueRun(env.DB, domain.id);
    const payload: IssuePayload = { runId, domainId: domain.id };
    await withWorkflowInstance(workflowId, async (instance) => {
      await instance.modify(async (modifier) => {
      await modifier.mockStepResult({ name: "load" }, {
        domain,
        identifiers: [
          { type: "dns", value: domain.name },
          { type: "dns", value: `*.${domain.name}` },
        ],
        previousCertificate: null,
      });
      await modifier.mockStepResult({ name: "ensure-account" }, {
        environment: "staging",
        accountUrl: "https://acme.example/account/1",
        thumbprint: "thumbprint",
      });
      await modifier.mockStepResult({ name: "new-order" }, {
        orderUrl: "https://acme.example/order/1",
        authorizations: ["https://acme.example/authz/1"],
      });
      await modifier.mockStepResult({ name: "publish-txt" }, { authorizations: [], targets: [] });
      await modifier.mockStepResult({ name: "wait-propagation" }, { mocked: true });
      await modifier.mockStepResult({ name: "accept-challenges" }, { mocked: true });
      await modifier.mockStepResult({ name: "await-authz" }, { mocked: true });
      await modifier.mockStepResult({ name: "key+csr" }, {
        certificateId: runId,
        r2Prefix: `certs/${domain.name}/${runId}`,
        csrB64u: "AQ",
        publicJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
      });
      await modifier.mockStepResult({ name: "finalize+store" }, {
        certificateId: runId,
        r2Prefix: `certs/${domain.name}/${runId}`,
        serial: "serial",
        fingerprintSha256: "a".repeat(64),
        sans: [domain.name, `*.${domain.name}`],
        notBefore: new Date().toISOString(),
        notAfter: new Date(Date.now() + 90 * 24 * 60 * 60_000).toISOString(),
      });
      await modifier.disableRetryDelays();
      });

      await env.ISSUANCE.create({ id: workflowId, params: payload });
      await instance.waitForStatus("complete");

      await expect(instance.getOutput()).resolves.toMatchObject({ runId, status: "succeeded", certificateId: runId });
      expect(await getIssueRun(env.DB, runId)).toMatchObject({ status: "succeeded", phase: "complete" });
      await expect(instance.waitForStepResult({ name: "cleanup-txt" })).resolves.toEqual({ deleted: 0 });
    });
  });

  it("still runs cleanup and marks the run failed when an issuance step errors", async () => {
    const domain = await seedDomain(env.DB);
    const { runId, workflowId } = await seedIssueRun(env.DB, domain.id);
    const payload: IssuePayload = { runId, domainId: domain.id };
    await withWorkflowInstance(workflowId, async (instance) => {
      await instance.modify(async (modifier) => {
      await modifier.mockStepResult({ name: "load" }, {
        domain,
        identifiers: [{ type: "dns", value: domain.name }],
        previousCertificate: null,
      });
      await modifier.mockStepResult({ name: "ensure-account" }, {
        environment: "staging",
        accountUrl: "https://acme.example/account/1",
        thumbprint: "thumbprint",
      });
      await modifier.mockStepResult({ name: "new-order" }, {
        orderUrl: "https://acme.example/order/1",
        authorizations: ["https://acme.example/authz/1"],
      });
      await modifier.mockStepResult({ name: "publish-txt" }, { authorizations: [], targets: [] });
      await modifier.mockStepResult({ name: "wait-propagation" }, { mocked: true });
      await modifier.mockStepResult({ name: "accept-challenges" }, { mocked: true });
      await modifier.mockStepError({ name: "await-authz" }, new Error("mock authorization failure"));
      await modifier.disableRetryDelays();
      });

      await env.ISSUANCE.create({ id: workflowId, params: payload });
      await instance.waitForStatus("complete");

      await expect(instance.getOutput()).resolves.toMatchObject({
        runId,
        status: "failed",
        error: "mock authorization failure",
      });
      expect(await getIssueRun(env.DB, runId)).toMatchObject({
        status: "failed",
        phase: "failed",
        error: "mock authorization failure",
      });
      await expect(instance.waitForStepResult({ name: "cleanup-txt" })).resolves.toEqual({ deleted: 0 });
    });
  });
});

type WorkflowInstanceInspector = Awaited<ReturnType<typeof introspectWorkflowInstance>>;

async function withWorkflowInstance<T>(
  workflowId: string,
  callback: (instance: WorkflowInstanceInspector) => Promise<T>,
): Promise<T> {
  const instance = await introspectWorkflowInstance(env.ISSUANCE, workflowId);
  try {
    return await callback(instance);
  } finally {
    await instance.dispose();
  }
}
