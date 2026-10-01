import type { IssueWorkflowCreator } from "../issue/trigger";
import type { AccessConfig } from "../auth/access";

export interface AdminOptions {
  /** Test seam: fetch implementation for the Cloudflare API and JWKS retrieval. */
  fetcher?: typeof fetch;
  /** Test seam: workflow creator used by POST /domains/:id/issue. */
  issuance?: IssueWorkflowCreator;
  /** Test seam: Access configuration (defaults to the values from env). */
  access?: AccessConfig;
}

export interface AdminDependencies {
  db: D1Database;
  bucket: R2Bucket;
  issuance: IssueWorkflowCreator;
  fetcher: typeof fetch;
  dnsApiToken: string;
  envelopeKey: string;
  /** ACME directory of this deployment; issuance and revocation must agree with it. */
  directoryUrl: string;
  /** Verified Access identity — the actor recorded in the audit log. */
  actor: string;
}

export type AdminHandler = (
  deps: AdminDependencies,
  request: Request,
  params: Record<string, string>,
) => Promise<Response>;

export function createAdminDependencies(
  env: Env,
  actor: string,
  options: AdminOptions = {},
): AdminDependencies {
  return {
    db: env.DB,
    bucket: env.CERTS,
    issuance: options.issuance ?? env.ISSUANCE,
    fetcher: options.fetcher ?? globalThis.fetch,
    dnsApiToken: env.CF_DNS_API_TOKEN,
    envelopeKey: env.ENVELOPE_KEY,
    directoryUrl: env.ACME_DIRECTORY,
    actor,
  };
}
