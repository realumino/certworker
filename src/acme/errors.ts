export interface AcmeSubproblem {
  type?: string;
  detail?: string;
  status?: number;
  identifier?: { type?: string; value?: string };
  [key: string]: unknown;
}

export interface AcmeProblem {
  type?: string;
  detail?: string;
  status?: number;
  subproblems?: AcmeSubproblem[];
  [key: string]: unknown;
}

export class AcmeError extends Error {
  readonly type?: string;
  readonly detail: string;
  readonly status?: number;
  readonly subproblems?: AcmeSubproblem[];

  constructor(
    readonly problem: AcmeProblem,
    readonly responseStatus: number,
    readonly retryAfterSeconds?: number,
    readonly rawBody?: string,
  ) {
    const detail = typeof problem.detail === "string" ? problem.detail : "ACME request failed";
    super(detail);
    this.name = "AcmeError";
    this.type = typeof problem.type === "string" ? problem.type : undefined;
    this.detail = detail;
    this.status = typeof problem.status === "number" ? problem.status : undefined;
    this.subproblems = Array.isArray(problem.subproblems) ? problem.subproblems : undefined;
  }

  static fromResponse(
    responseStatus: number,
    body: string,
    retryAfterSeconds?: number,
  ): AcmeError {
    let problem: AcmeProblem;
    try {
      const parsed: unknown = JSON.parse(body);
      problem = isObject(parsed) ? parsed : { detail: body || `ACME returned HTTP ${responseStatus}` };
    } catch {
      problem = { detail: body || `ACME returned HTTP ${responseStatus}` };
    }

    return new AcmeError(problem, responseStatus, retryAfterSeconds, body);
  }

  static fromProblem(
    problem: AcmeProblem,
    responseStatus: number,
    retryAfterSeconds?: number,
  ): AcmeError {
    return new AcmeError(problem, responseStatus, retryAfterSeconds);
  }
}

export class AcmeProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AcmeProtocolError";
  }
}

export class AcmeTimeoutError extends Error {
  constructor(readonly operation: string, readonly timeoutMs: number) {
    super(`Timed out waiting for ${operation} after ${Math.ceil(timeoutMs / 1000)} seconds`);
    this.name = "AcmeTimeoutError";
  }
}

export function parseRetryAfter(value: string | null, nowMs = Date.now()): number | undefined {
  if (value === null) return undefined;

  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) {
    const seconds = Number(trimmed);
    return Number.isSafeInteger(seconds) ? seconds : undefined;
  }

  if (!/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(trimmed)) {
    return undefined;
  }
  const timestamp = Date.parse(trimmed);
  if (!Number.isFinite(timestamp)) return undefined;
  return Math.max(0, Math.ceil((timestamp - nowMs) / 1000));
}

export function isBadNonce(error: unknown): error is AcmeError {
  return error instanceof AcmeError && hasAcmeType(error.type, "badNonce");
}

export function isRateLimited(error: unknown): error is AcmeError {
  return (
    error instanceof AcmeError &&
    (error.responseStatus === 429 || hasAcmeType(error.type, "rateLimited"))
  );
}

/** RFC 8555 §7.6: revoking an already-revoked certificate is treated as success. */
export function isAlreadyRevoked(error: unknown): error is AcmeError {
  return error instanceof AcmeError && hasAcmeType(error.type, "alreadyRevoked");
}

function hasAcmeType(type: string | undefined, name: string): boolean {
  return type === name || type?.endsWith(`:${name}`) === true || type?.endsWith(`/${name}`) === true;
}

function isObject(value: unknown): value is AcmeProblem {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
