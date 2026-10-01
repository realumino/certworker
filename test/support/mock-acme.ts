import "@abraham/reflection";
import * as x509 from "@peculiar/x509";
import type { AcmeIdentifier } from "../../src/acme/client";
import { b64uDecode } from "../../src/crypto/base64url";
import { derToPem } from "../../src/crypto/pem";
import { parseCsr } from "../../src/crypto/csr";
import { generateEcP256KeyPair } from "../../src/crypto/keys";
import type { CapturedRequest } from "./fake-fetch";

const DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory";
const BASE_URL = "https://acme-staging-v02.api.letsencrypt.org";

export interface MockAcmeOptions {
  invalidAuthorization?: boolean;
  /** POST /revoke-cert answers the RFC 8555 alreadyRevoked problem. */
  alreadyRevoked?: boolean;
  /** POST /revoke-cert answers a generic 403 problem. */
  revokeFails?: boolean;
}

export class MockAcme {
  private readonly acceptedChallenges = new Set<number>();
  private readonly options: MockAcmeOptions;
  private identifiers: AcmeIdentifier[] = [];
  private certificatePem = "";
  private finalized = false;
  private nonceCount = 0;
  /** base64url DER payloads accepted by /revoke-cert. */
  readonly revokedCertificates: string[] = [];

  constructor(options: MockAcmeOptions = {}) {
    this.options = options;
  }

  async handle({ request, url, body }: CapturedRequest): Promise<Response | undefined> {
    if (url.origin !== BASE_URL) return undefined;
    const path = url.pathname;

    if (request.method === "GET" && url.href === DIRECTORY_URL) {
      return this.reply({
        newNonce: `${BASE_URL}/new-nonce`,
        newAccount: `${BASE_URL}/new-account`,
        newOrder: `${BASE_URL}/new-order`,
        revokeCert: `${BASE_URL}/revoke-cert`,
      });
    }
    if (request.method === "HEAD" && path === "/new-nonce") {
      return new Response(null, { status: 204, headers: this.nonceHeaders() });
    }
    if (request.method === "POST" && path === "/new-account") {
      return this.reply({}, 201, { Location: `${BASE_URL}/account/1` });
    }
    if (request.method === "POST" && path === "/new-order") {
      const payload = readJwsPayload(body);
      if (!isObject(payload) || !Array.isArray(payload.identifiers)) return this.problem("newOrder needs identifiers", 400);
      this.identifiers = payload.identifiers.filter(isIdentifier);
      if (this.identifiers.length === 0) return this.problem("newOrder has no DNS identifiers", 400);
      return this.reply(this.order("pending"), 201, { Location: `${BASE_URL}/order/1` });
    }

    const authorizationMatch = path.match(/^\/authz\/(\d+)$/);
    if (request.method === "POST" && authorizationMatch) {
      const index = Number(authorizationMatch[1]);
      const identifier = this.identifiers[index];
      if (!identifier) return this.problem("unknown authorization", 404);
      const accepted = this.acceptedChallenges.has(index);
      const invalid = accepted && this.options.invalidAuthorization === true;
      const challengeStatus = accepted ? (invalid ? "invalid" : "valid") : "pending";
      const authzStatus = accepted ? (invalid ? "invalid" : "valid") : "pending";
      return this.reply({
        identifier: { type: "dns", value: identifier.value.replace(/^\*\./, "") },
        wildcard: identifier.value.startsWith("*."),
        status: authzStatus,
        challenges: [{
          type: "dns-01",
          url: `${BASE_URL}/challenge/${index}`,
          status: challengeStatus,
          token: `token-${index}-abc123`,
          ...(invalid ? {
            error: {
              type: "urn:ietf:params:acme:error:unauthorized",
              detail: "mock authorization rejected",
            },
          } : {}),
        }],
        ...(invalid ? {
          error: {
            type: "urn:ietf:params:acme:error:unauthorized",
            detail: "mock authorization rejected",
          },
        } : {}),
      });
    }

    const challengeMatch = path.match(/^\/challenge\/(\d+)$/);
    if (request.method === "POST" && challengeMatch) {
      const index = Number(challengeMatch[1]);
      this.acceptedChallenges.add(index);
      return this.reply({
        type: "dns-01",
        url: `${BASE_URL}/challenge/${index}`,
        status: "processing",
      });
    }

    if (request.method === "POST" && path === "/order/1") {
      if (this.finalized) {
        return this.reply(this.order("valid", `${BASE_URL}/certificate/1`));
      }
      return this.reply(this.order(this.acceptedChallenges.size === this.identifiers.length ? "ready" : "pending"));
    }
    if (request.method === "POST" && path === "/finalize/1") {
      const payload = readJwsPayload(body);
      if (!isObject(payload) || typeof payload.csr !== "string") return this.problem("finalize needs a CSR", 400);
      this.certificatePem = await issueTestCertificate(payload.csr);
      this.finalized = true;
      return this.reply(this.order("processing"));
    }
    if (request.method === "POST" && path === "/certificate/1") {
      if (!this.finalized) return this.problem("certificate is not ready", 400);
      return new Response(this.certificatePem, {
        status: 200,
        headers: { ...this.nonceHeaders(), "Content-Type": "application/pem-certificate-chain" },
      });
    }
    if (request.method === "POST" && path === "/revoke-cert") {
      const payload = readJwsPayload(body);
      if (!isObject(payload) || typeof payload.certificate !== "string") {
        return this.problem("revokeCert needs a certificate", 400);
      }
      if (this.options.revokeFails === true) {
        return this.problem("mock revocation rejected", 403, "urn:ietf:params:acme:error:unauthorized");
      }
      if (this.options.alreadyRevoked === true) {
        return this.problem(
          "mock certificate is already revoked",
          400,
          "urn:ietf:params:acme:error:alreadyRevoked",
        );
      }
      this.revokedCertificates.push(payload.certificate);
      return this.reply({}, 200);
    }

    return undefined;
  }

  private order(status: string, certificate?: string): Record<string, unknown> {
    return {
      status,
      identifiers: this.identifiers,
      authorizations: this.identifiers.map((_, index) => `${BASE_URL}/authz/${index}`),
      finalize: `${BASE_URL}/finalize/1`,
      ...(certificate ? { certificate } : {}),
    };
  }

  private problem(detail: string, status: number, type = "urn:ietf:params:acme:error:malformed"): Response {
    return this.reply({ type, detail, status }, status);
  }

  private reply(value: unknown, status = 200, extraHeaders: HeadersInit = {}): Response {
    return Response.json(value, {
      status,
      headers: { ...this.nonceHeaders(), ...Object.fromEntries(new Headers(extraHeaders).entries()) },
    });
  }

  private nonceHeaders(): HeadersInit {
    this.nonceCount += 1;
    return { "Replay-Nonce": `mock_nonce_${this.nonceCount}` };
  }
}

async function issueTestCertificate(csrB64u: string): Promise<string> {
  const csrPem = derToPem(b64uDecode(csrB64u), "CERTIFICATE REQUEST");
  const csr = await parseCsr(csrPem);
  const leafPublicKey = await crypto.subtle.importKey(
    "jwk",
    csr.publicKeyJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
  const issuerKey = await generateEcP256KeyPair();
  const certificate = await x509.X509CertificateGenerator.create({
    subject: `CN=${csr.commonName}`,
    issuer: "CN=Offline ACME Test Issuer",
    publicKey: leafPublicKey,
    signingKey: issuerKey.privateKey,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: [
      new x509.SubjectAlternativeNameExtension(
        csr.sans.map((value) => ({ type: "dns" as const, value })),
        false,
      ),
    ],
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 90 * 24 * 60 * 60_000),
  });
  return certificate.toString();
}

function readJwsPayload(body: string): unknown {
  let jws: unknown;
  try {
    jws = JSON.parse(body);
  } catch {
    return undefined;
  }
  if (!isObject(jws) || typeof jws.payload !== "string" || jws.payload.length === 0) return undefined;
  try {
    return JSON.parse(new TextDecoder().decode(b64uDecode(jws.payload)));
  } catch {
    return undefined;
  }
}

function isIdentifier(value: unknown): value is AcmeIdentifier {
  return isObject(value) && value.type === "dns" && typeof value.value === "string";
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A real parseable leaf PEM (self-signed) for R2 fixtures consumed by revoke flows. */
export async function createSelfSignedCertificatePem(commonName: string): Promise<string> {
  const keyPair = await generateEcP256KeyPair();
  const certificate = await x509.X509CertificateGenerator.create({
    subject: `CN=${commonName}`,
    issuer: "CN=Offline ACME Test Issuer",
    publicKey: keyPair.publicKey,
    signingKey: keyPair.privateKey,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: [
      new x509.SubjectAlternativeNameExtension([{ type: "dns", value: commonName }], false),
    ],
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 90 * 24 * 60 * 60_000),
  });
  return certificate.toString();
}
