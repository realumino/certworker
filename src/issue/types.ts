export interface IssuePayload {
  runId: string;
  domainId: string;
}

export type IssueTrigger = "manual" | "retry" | "cron";

export type AcmeEnvironment = "staging" | "production";
