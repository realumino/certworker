import { b64uEncode } from "./base64url";

export interface EcPublicJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
}

const REQUIRED_JWK_MEMBERS: Record<string, readonly string[]> = {
  EC: ["crv", "kty", "x", "y"],
  RSA: ["e", "kty", "n"],
  oct: ["k", "kty"],
};

export async function generateEcP256KeyPair(): Promise<CryptoKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );

  if (!("publicKey" in keyPair) || !("privateKey" in keyPair)) {
    throw new TypeError("Web Crypto did not generate an EC key pair");
  }

  return keyPair;
}

export async function exportPublicJwk(publicKey: CryptoKey): Promise<EcPublicJwk> {
  const exported = await crypto.subtle.exportKey("jwk", publicKey);

  if (exported instanceof ArrayBuffer) {
    throw new TypeError("Web Crypto did not export a JWK");
  }
  const jwk = exported;

  if (
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string"
  ) {
    throw new TypeError("Expected an ECDSA P-256 public key");
  }

  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
}

export async function jwkThumbprint<T extends JsonWebKey>(jwk: T): Promise<string> {
  const keyType = jwk.kty;
  if (typeof keyType !== "string") {
    throw new TypeError("JWK is missing required member: kty");
  }

  const members = REQUIRED_JWK_MEMBERS[keyType];

  if (members === undefined) {
    throw new RangeError(`Unsupported JWK key type: ${jwk.kty}`);
  }

  const values: Record<string, string | undefined> = {
    crv: jwk.crv,
    e: jwk.e,
    k: jwk.k,
    kty: keyType,
    n: jwk.n,
    x: jwk.x,
    y: jwk.y,
  };
  const canonicalMembers: string[] = [];

  for (const member of members) {
    const value = values[member];
    if (typeof value !== "string") {
      throw new TypeError(`JWK is missing required member: ${member}`);
    }
    canonicalMembers.push(`${JSON.stringify(member)}:${JSON.stringify(value)}`);
  }

  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`{${canonicalMembers.join(",")}}`),
  );

  return b64uEncode(new Uint8Array(digest));
}
