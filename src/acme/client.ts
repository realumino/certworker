import { AcmeError, AcmeProtocolError, AcmeTimeoutError, isBadNonce, parseRetryAfter } from "./errors";
import type { AcmeProblem } from "./errors";
import { b64uEncode } from "../crypto/base64url";
import { exportPublicJwk, type EcPublicJwk } from "../crypto/keys";
import { signFlattenedJws } from "./jws";

const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_POLL_INTERVAL_MS = 3_000;
const DEFAULT_POLL_TIMEOUT_MS = 5 * 60_000;
const REPLAY_NONCE_HEADER = "Replay-Nonce";

export interface AcmeDirectory {
  newNonce: string;
  newAccount: string;
  newOrder: string;
  revokeCert?: string;
  keyChange?: string;
  meta?: Record<string, unknown>;
}

export interface AcmeIdentifier {
  type: "dns";
  value: string;
}

export type AcmeOrderStatus = "pending" | "ready" | "processing" | "valid" | "invalid";

export interface AcmeOrder {
  url: string;
  status: AcmeOrderStatus;
  identifiers: AcmeIdentifier[];
  authorizations: string[];
  finalize: string;
  expires?: string;
  notBefore?: string;
  notAfter?: string;
  certificate?: string;
  error?: AcmeProblem;
}

export interface AcmeChallenge {
  type: string;
  url: string;
  status: string;
  token?: string;
  error?: AcmeProblem;
}

export interface AcmeAuthorization {
  identifier: AcmeIdentifier;
  status: "pending" | "valid" | "invalid";
  challenges: AcmeChallenge[];
  expires?: string;
  wildcard?: boolean;
  error?: AcmeProblem;
}

export interface AcmeClientOptions {
  directoryUrl: string;
  accountKey: CryptoKeyPair;
  kid?: string;
  fetch?: typeof fetch;
  wait?: (ms: number) => Promise<void>;
  now?: () => number;
  requestTimeoutMs?: number;
}

export interface PollOptions {
  timeoutMs?: number;
  pollIntervalMs?: number;
}

interface JsonPostResult {
  body: Record<string, unknown>;
  responseStatus: number;
  retryAfterSeconds?: number;
  location?: string;
}

interface OrderRead {
  order: AcmeOrder;
  responseStatus: number;
  retryAfterSeconds?: number;
}

interface AuthorizationRead {
  authorization: AcmeAuthorization;
  responseStatus: number;
  retryAfterSeconds?: number;
}

export class AcmeClient {
  private readonly fetcher: typeof fetch;
  private readonly wait: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private readonly requestTimeoutMs: number;
  private replayNonce?: string;
  private directory?: AcmeDirectory;
  private publicJwk?: EcPublicJwk;
  private accountUrl?: string;

  constructor(options: AcmeClientOptions) {
    assertHttpsUrl(options.directoryUrl, "ACME directory URL");
    if (options.kid !== undefined) assertHttpsUrl(options.kid, "ACME account URL");

    this.directoryUrl = options.directoryUrl;
    this.accountKey = options.accountKey;
    this.accountUrl = options.kid;
    this.fetcher = options.fetch ?? globalThis.fetch;
    this.wait = options.wait ?? sleep;
    this.now = options.now ?? Date.now;
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;

    if (!Number.isFinite(this.requestTimeoutMs) || this.requestTimeoutMs <= 0) {
      throw new RangeError("requestTimeoutMs must be positive and finite");
    }
    if (this.accountKey.privateKey.type !== "private") throw new TypeError("ACME account key must be private");
  }

  private readonly directoryUrl: string;
  private readonly accountKey: CryptoKeyPair;

  get kid(): string | undefined {
    return this.accountUrl;
  }

  async getDirectory(): Promise<AcmeDirectory> {
    if (this.directory) return this.directory;

    const response = await this.fetchRaw(this.directoryUrl, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
    const body = await response.text();
    if (!response.ok) {
      throw AcmeError.fromResponse(
        response.status,
        body,
        parseRetryAfter(response.headers.get("Retry-After"), this.now()),
      );
    }

    const value = parseJsonObject(body, "ACME directory");
    const directory: AcmeDirectory = {
      newNonce: requiredString(value, "newNonce", "ACME directory"),
      newAccount: requiredString(value, "newAccount", "ACME directory"),
      newOrder: requiredString(value, "newOrder", "ACME directory"),
      revokeCert: optionalString(value, "revokeCert"),
      keyChange: optionalString(value, "keyChange"),
      meta: isObject(value.meta) ? value.meta : undefined,
    };
    assertHttpsUrl(directory.newNonce, "ACME newNonce URL");
    assertHttpsUrl(directory.newAccount, "ACME newAccount URL");
    assertHttpsUrl(directory.newOrder, "ACME newOrder URL");
    if (directory.revokeCert) assertHttpsUrl(directory.revokeCert, "ACME revokeCert URL");
    if (directory.keyChange) assertHttpsUrl(directory.keyChange, "ACME keyChange URL");

    this.directory = directory;
    return directory;
  }

  async ensureAccount(): Promise<string> {
    if (this.accountUrl) return this.accountUrl;

    const directory = await this.getDirectory();
    const publicJwk = await this.getPublicJwk();
    const response = await this.signedPost(
      directory.newAccount,
      { termsOfServiceAgreed: true },
      "jwk",
    );
    const accountUrl = response.headers.get("Location");
    if (!accountUrl) throw new AcmeProtocolError("ACME newAccount response is missing its Location header");
    assertHttpsUrl(accountUrl, "ACME account URL");

    this.publicJwk = publicJwk;
    this.accountUrl = accountUrl;
    return accountUrl;
  }

  async newOrder(identifiers: AcmeIdentifier[]): Promise<AcmeOrder> {
    if (identifiers.length === 0) throw new TypeError("An ACME order requires at least one identifier");
    if (identifiers.some(({ type, value }) => type !== "dns" || value.length === 0)) {
      throw new TypeError("ACME order identifiers must be non-empty DNS names");
    }

    await this.ensureAccount();
    const directory = await this.getDirectory();
    const result = await this.postJson(directory.newOrder, { identifiers }, "kid");
    const location = requireLocation(result, "ACME newOrder");
    return parseOrder(result.body, location);
  }

  async getOrder(url: string): Promise<AcmeOrder> {
    return (await this.readOrder(url)).order;
  }

  async getAuthorization(url: string): Promise<AcmeAuthorization> {
    return (await this.readAuthorization(url)).authorization;
  }

  async acceptChallenge(url: string): Promise<AcmeChallenge> {
    const response = await this.signedPost(url, {}, "kid");
    const text = await response.text();
    if (text.trim().length === 0) return { type: "dns-01", url, status: "processing" };
    const body = parseJsonObject(text, "ACME challenge response");
    return parseChallenge(body, url);
  }

  async finalizeOrder(finalizeUrl: string, csrDer: Uint8Array, orderUrl?: string): Promise<AcmeOrder> {
    if (csrDer.length === 0) throw new TypeError("A non-empty DER-encoded CSR is required");
    const result = await this.postJson(finalizeUrl, { csr: b64uEncode(csrDer) }, "kid");
    return parseOrder(result.body, orderUrl ?? result.location ?? finalizeUrl);
  }

  async downloadCertificate(url: string): Promise<string> {
    const response = await this.signedPost(url, null, "kid", "application/pem-certificate-chain");
    const pem = new TextDecoder().decode(await response.arrayBuffer());
    if (!pem.includes("-----BEGIN CERTIFICATE-----")) {
      throw new AcmeProtocolError("ACME certificate response did not contain a PEM certificate chain");
    }
    return pem;
  }

  /** RFC 8555 §7.6: POST the base64url DER of the certificate to `revokeCert`. */
  async revokeCertificate(certificateDer: Uint8Array): Promise<void> {
    if (certificateDer.length === 0) throw new TypeError("A non-empty DER-encoded certificate is required");
    const directory = await this.getDirectory();
    if (!directory.revokeCert) throw new AcmeProtocolError("ACME directory does not advertise revokeCert");
    await this.signedPost(directory.revokeCert, { certificate: b64uEncode(certificateDer) }, "kid");
  }

  async waitForAuthorizationValid(url: string, options: PollOptions = {}): Promise<AcmeAuthorization> {
    const timeoutMs = options.timeoutMs ?? DEFAULT_POLL_TIMEOUT_MS;
    const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    const deadline = this.now() + timeoutMs;
    const maxAttempts = maxPollAttempts(timeoutMs, pollIntervalMs);

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const result = await this.readAuthorization(url);
      const authorization = result.authorization;
      if (authorization.status === "valid") return authorization;
      if (authorization.status === "invalid") {
        const problem = authorization.error ?? {
          type: "urn:ietf:params:acme:error:malformed",
          detail: `Authorization for ${authorization.identifier.value} became invalid`,
        };
        throw AcmeError.fromProblem(problem, result.responseStatus, result.retryAfterSeconds);
      }
      await this.waitForNextPoll("authorization validation", timeoutMs, deadline, pollIntervalMs, result.retryAfterSeconds);
    }

    throw new AcmeTimeoutError("authorization validation", timeoutMs);
  }

  async waitForOrderReady(url: string, options: PollOptions = {}): Promise<AcmeOrder> {
    const timeoutMs = options.timeoutMs ?? DEFAULT_POLL_TIMEOUT_MS;
    const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    const deadline = this.now() + timeoutMs;
    const maxAttempts = maxPollAttempts(timeoutMs, pollIntervalMs);

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const result = await this.readOrder(url);
      if (result.order.status === "ready") return result.order;
      if (result.order.status === "invalid") throw invalidOrderError(result.order, result);
      if (result.order.status !== "pending") {
        throw new AcmeProtocolError(`Expected order ${url} to become ready, received status ${result.order.status}`);
      }
      await this.waitForNextPoll("order readiness", timeoutMs, deadline, pollIntervalMs, result.retryAfterSeconds);
    }

    throw new AcmeTimeoutError("order readiness", timeoutMs);
  }

  async waitForOrderValid(url: string, options: PollOptions = {}): Promise<AcmeOrder> {
    const timeoutMs = options.timeoutMs ?? DEFAULT_POLL_TIMEOUT_MS;
    const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    const deadline = this.now() + timeoutMs;
    const maxAttempts = maxPollAttempts(timeoutMs, pollIntervalMs);

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const result = await this.readOrder(url);
      if (result.order.status === "valid") return result.order;
      if (result.order.status === "invalid") throw invalidOrderError(result.order, result);
      if (result.order.status !== "processing") {
        throw new AcmeProtocolError(`Expected finalized order ${url} to become valid, received status ${result.order.status}`);
      }
      await this.waitForNextPoll("certificate issuance", timeoutMs, deadline, pollIntervalMs, result.retryAfterSeconds);
    }

    throw new AcmeTimeoutError("certificate issuance", timeoutMs);
  }

  private async readOrder(url: string): Promise<OrderRead> {
    const result = await this.postJson(url, null, "kid");
    return {
      order: parseOrder(result.body, url),
      responseStatus: result.responseStatus,
      retryAfterSeconds: result.retryAfterSeconds,
    };
  }

  private async readAuthorization(url: string): Promise<AuthorizationRead> {
    const result = await this.postJson(url, null, "kid");
    return {
      authorization: parseAuthorization(result.body),
      responseStatus: result.responseStatus,
      retryAfterSeconds: result.retryAfterSeconds,
    };
  }

  private async postJson(
    url: string,
    payload: Record<string, unknown> | null,
    authentication: "jwk" | "kid",
  ): Promise<JsonPostResult> {
    const response = await this.signedPost(url, payload, authentication);
    const text = await response.text();
    return {
      body: parseJsonObject(text, "ACME response"),
      responseStatus: response.status,
      retryAfterSeconds: parseRetryAfter(response.headers.get("Retry-After"), this.now()),
      location: response.headers.get("Location") ?? undefined,
    };
  }

  private async signedPost(
    url: string,
    payload: Record<string, unknown> | null,
    authentication: "jwk" | "kid",
    accept = "application/json",
  ): Promise<Response> {
    assertHttpsUrl(url, "ACME resource URL");
    if (authentication === "kid") await this.ensureAccount();
    const directory = await this.getDirectory();
    const publicJwk = authentication === "jwk" ? await this.getPublicJwk() : undefined;

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const nonce = await this.takeNonce(directory);
      const header = authentication === "jwk"
        ? { alg: "ES256" as const, jwk: publicJwk, nonce, url }
        : { alg: "ES256" as const, kid: this.accountUrl, nonce, url };
      const body = payload === null ? null : new TextEncoder().encode(JSON.stringify(payload));
      const jws = await signFlattenedJws(this.accountKey.privateKey, header, body);
      const response = await this.fetchRaw(url, {
        method: "POST",
        headers: {
          Accept: accept,
          "Content-Type": "application/jose+json",
        },
        body: JSON.stringify(jws),
      });

      if (response.ok) return response;

      const responseBody = await response.text();
      const retryAfterSeconds = parseRetryAfter(response.headers.get("Retry-After"), this.now());
      const error = AcmeError.fromResponse(response.status, responseBody, retryAfterSeconds);
      if (!isBadNonce(error) || attempt === 1) throw error;
    }

    throw new AcmeProtocolError("ACME badNonce retry did not complete");
  }

  private async takeNonce(directory: AcmeDirectory): Promise<string> {
    if (this.replayNonce) {
      const nonce = this.replayNonce;
      this.replayNonce = undefined;
      return nonce;
    }

    const response = await this.fetchRaw(directory.newNonce, { method: "HEAD" });
    if (!response.ok) {
      const body = await response.text();
      throw AcmeError.fromResponse(
        response.status,
        body,
        parseRetryAfter(response.headers.get("Retry-After"), this.now()),
      );
    }

    if (!this.replayNonce) throw new AcmeProtocolError("ACME newNonce response is missing a valid Replay-Nonce header");
    const nonce = this.replayNonce;
    this.replayNonce = undefined;
    return nonce;
  }

  private async getPublicJwk(): Promise<EcPublicJwk> {
    this.publicJwk ??= await exportPublicJwk(this.accountKey.publicKey);
    return this.publicJwk;
  }

  private async fetchRaw(url: string, init: RequestInit): Promise<Response> {
    const headers = new Headers(init.headers);
    headers.set("User-Agent", "ssl-cert-worker/0.1");
    // Call the fetcher standalone: workerd's global `fetch` throws an
    // "Illegal invocation" TypeError when invoked as a method of another object
    // (i.e. `this.fetcher(...)`), which is the production code path.
    const fetcher = this.fetcher;
    const response = await fetcher(url, {
      ...init,
      headers,
      redirect: "manual",
      signal: AbortSignal.timeout(this.requestTimeoutMs),
    });
    this.captureNonce(response.headers.get(REPLAY_NONCE_HEADER));
    if (response.status >= 300 && response.status < 400) {
      throw new AcmeProtocolError(`ACME resource unexpectedly redirected: ${url}`);
    }
    return response;
  }

  private captureNonce(value: string | null): void {
    if (value === null) return;
    const nonce = value.trim();
    if (/^[A-Za-z0-9_-]+$/.test(nonce)) this.replayNonce = nonce;
  }

  private async waitForNextPoll(
    operation: string,
    timeoutMs: number,
    deadline: number,
    pollIntervalMs: number,
    retryAfterSeconds?: number,
  ): Promise<void> {
    const remaining = deadline - this.now();
    if (remaining <= 0) throw new AcmeTimeoutError(operation, timeoutMs);
    const requestedDelay = retryAfterSeconds === undefined ? pollIntervalMs : retryAfterSeconds * 1000;
    await this.wait(Math.max(0, Math.min(requestedDelay, remaining)));
  }
}

function parseOrder(value: Record<string, unknown>, url: string): AcmeOrder {
  const status = value.status;
  if (!isOrderStatus(status)) throw new AcmeProtocolError(`ACME order has an invalid status: ${String(status)}`);
  if (!Array.isArray(value.authorizations) || !value.authorizations.every((entry) => typeof entry === "string")) {
    throw new AcmeProtocolError("ACME order is missing its authorization URLs");
  }
  if (typeof value.finalize !== "string") throw new AcmeProtocolError("ACME order is missing its finalize URL");
  assertHttpsUrl(value.finalize, "ACME order finalize URL");
  const identifiers = parseIdentifiers(value.identifiers);
  const authorizations = value.authorizations;
  for (const authorization of authorizations) assertHttpsUrl(authorization, "ACME authorization URL");

  const certificate = optionalString(value, "certificate");
  if (certificate) assertHttpsUrl(certificate, "ACME certificate URL");
  const problem = optionalProblem(value.error);

  return {
    url,
    status,
    identifiers,
    authorizations,
    finalize: value.finalize,
    expires: optionalString(value, "expires"),
    notBefore: optionalString(value, "notBefore"),
    notAfter: optionalString(value, "notAfter"),
    certificate,
    error: problem,
  };
}

function parseAuthorization(value: Record<string, unknown>): AcmeAuthorization {
  const identifier = parseIdentifiers([value.identifier])[0];
  if (value.status !== "pending" && value.status !== "valid" && value.status !== "invalid") {
    throw new AcmeProtocolError(`ACME authorization has an invalid status: ${String(value.status)}`);
  }
  if (!Array.isArray(value.challenges)) throw new AcmeProtocolError("ACME authorization is missing its challenges");

  return {
    identifier,
    status: value.status,
    challenges: value.challenges.map((challenge) => {
      if (!isObject(challenge)) throw new AcmeProtocolError("ACME authorization contains a malformed challenge");
      return parseChallenge(challenge);
    }),
    expires: optionalString(value, "expires"),
    wildcard: typeof value.wildcard === "boolean" ? value.wildcard : undefined,
    error: optionalProblem(value.error),
  };
}

function parseChallenge(value: Record<string, unknown>, fallbackUrl?: string): AcmeChallenge {
  const type = requiredString(value, "type", "ACME challenge");
  const url = optionalString(value, "url") ?? fallbackUrl;
  const status = requiredString(value, "status", "ACME challenge");
  if (!url) throw new AcmeProtocolError("ACME challenge is missing its URL");
  assertHttpsUrl(url, "ACME challenge URL");

  return {
    type,
    url,
    status,
    token: optionalString(value, "token"),
    error: optionalProblem(value.error),
  };
}

function parseIdentifiers(value: unknown): AcmeIdentifier[] {
  if (!Array.isArray(value) || value.length === 0) throw new AcmeProtocolError("ACME resource is missing its identifiers");
  return value.map((identifier) => {
    if (!isObject(identifier) || identifier.type !== "dns" || typeof identifier.value !== "string") {
      throw new AcmeProtocolError("ACME resource contains an invalid DNS identifier");
    }
    return { type: "dns", value: identifier.value };
  });
}

function invalidOrderError(order: AcmeOrder, result: OrderRead): AcmeError {
  const problem = order.error ?? {
    type: "urn:ietf:params:acme:error:malformed",
    detail: `ACME order ${order.url} became invalid`,
  };
  return AcmeError.fromProblem(problem, result.responseStatus, result.retryAfterSeconds);
}

function optionalProblem(value: unknown): AcmeProblem | undefined {
  return isObject(value) ? value : undefined;
}

function parseJsonObject(text: string, label: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new AcmeProtocolError(`${label} was not valid JSON`);
  }
  if (!isObject(parsed)) throw new AcmeProtocolError(`${label} was not a JSON object`);
  return parsed;
}

function requiredString(value: Record<string, unknown>, key: string, label: string): string {
  const result = value[key];
  if (typeof result !== "string" || result.length === 0) {
    throw new AcmeProtocolError(`${label} is missing ${key}`);
  }
  return result;
}

function optionalString(value: Record<string, unknown>, key: string): string | undefined {
  const result = value[key];
  return typeof result === "string" ? result : undefined;
}

function requireLocation(result: JsonPostResult, operation: string): string {
  if (!result.location) throw new AcmeProtocolError(`${operation} response is missing its Location header`);
  assertHttpsUrl(result.location, `${operation} Location URL`);
  return result.location;
}

function isOrderStatus(value: unknown): value is AcmeOrderStatus {
  return value === "pending" || value === "ready" || value === "processing" || value === "valid" || value === "invalid";
}

function assertHttpsUrl(value: string, label: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new AcmeProtocolError(`${label} is not an absolute URL`);
  }
  if (parsed.protocol !== "https:") throw new AcmeProtocolError(`${label} must use HTTPS`);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function maxPollAttempts(timeoutMs: number, pollIntervalMs: number): number {
  if (!Number.isFinite(timeoutMs) || !Number.isFinite(pollIntervalMs) || timeoutMs < 0 || pollIntervalMs <= 0) {
    throw new RangeError("Poll timeout must be non-negative and interval must be positive");
  }
  return Math.max(1, Math.ceil(timeoutMs / pollIntervalMs) + 2);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
