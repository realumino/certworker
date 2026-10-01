import { b64uEncode } from "../crypto/base64url";
import type { EcPublicJwk } from "../crypto/keys";

export interface JwsHeader {
  alg: "ES256";
  jwk?: EcPublicJwk;
  kid?: string;
  nonce?: string;
  url?: string;
}

export interface FlattenedJws {
  protected: string;
  payload: string;
  signature: string;
}

export async function signFlattenedJws(
  signingKey: CryptoKey,
  header: JwsHeader,
  payload: Uint8Array | null,
): Promise<FlattenedJws> {
  if (header.alg !== "ES256") {
    throw new TypeError("Only ES256 JWS signatures are supported");
  }
  if (header.jwk !== undefined && header.kid !== undefined) {
    throw new TypeError("A JWS protected header cannot contain both jwk and kid");
  }

  const protectedHeader: JwsHeader = { alg: "ES256" };
  if (header.jwk !== undefined) protectedHeader.jwk = header.jwk;
  if (header.kid !== undefined) protectedHeader.kid = header.kid;
  if (header.nonce !== undefined) protectedHeader.nonce = header.nonce;
  if (header.url !== undefined) protectedHeader.url = header.url;

  const protectedValue = b64uEncode(new TextEncoder().encode(JSON.stringify(protectedHeader)));
  const payloadValue = payload === null ? "" : b64uEncode(payload);
  const signingInput = new TextEncoder().encode(`${protectedValue}.${payloadValue}`);
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    signingKey,
    signingInput,
  );

  return {
    protected: protectedValue,
    payload: payloadValue,
    signature: b64uEncode(new Uint8Array(signature)),
  };
}
