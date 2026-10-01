import { describe, expect, it } from "vitest";
import { signFlattenedJws } from "../src/acme/jws";
import { b64uDecode, b64uEncode } from "../src/crypto/base64url";
import { exportPublicJwk, generateEcP256KeyPair } from "../src/crypto/keys";

async function verifyJws(
  jws: { protected: string; payload: string; signature: string },
  publicKey: CryptoKey,
  payload = jws.payload,
): Promise<boolean> {
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    b64uDecode(jws.signature),
    new TextEncoder().encode(`${jws.protected}.${payload}`),
  );
}

describe("ES256 flattened JWS", () => {
  it("produces the expected protected-header and payload encodings", async () => {
    const keyPair = await generateEcP256KeyPair();
    const payload = new TextEncoder().encode("Payload");
    const jws = await signFlattenedJws(keyPair.privateKey, { alg: "ES256" }, payload);

    expect(jws.protected).toBe("eyJhbGciOiJFUzI1NiJ9");
    expect(jws.payload).toBe("UGF5bG9hZA");
    expect(b64uDecode(jws.signature)).toHaveLength(64);
    await expect(verifyJws(jws, keyPair.publicKey)).resolves.toBe(true);
    await expect(verifyJws(jws, keyPair.publicKey, "UGF5bG9hZB")).resolves.toBe(false);
  });

  it("uses an empty POST-as-GET payload and signs the trailing dot", async () => {
    const keyPair = await generateEcP256KeyPair();
    const jws = await signFlattenedJws(keyPair.privateKey, { alg: "ES256" }, null);

    expect(jws.payload).toBe("");
    await expect(verifyJws(jws, keyPair.publicKey)).resolves.toBe(true);
  });

  it("serializes ACME kid headers in stable field order", async () => {
    const keyPair = await generateEcP256KeyPair();
    const jws = await signFlattenedJws(
      keyPair.privateKey,
      {
        alg: "ES256",
        nonce: "n0",
        url: "https://acme.example/new-order",
        kid: "k1",
      },
      null,
    );
    const expectedHeader =
      '{"alg":"ES256","kid":"k1","nonce":"n0","url":"https://acme.example/new-order"}';

    expect(jws.protected).toBe(b64uEncode(new TextEncoder().encode(expectedHeader)));
    expect(JSON.parse(new TextDecoder().decode(b64uDecode(jws.protected)))).toEqual({
      alg: "ES256",
      kid: "k1",
      nonce: "n0",
      url: "https://acme.example/new-order",
    });
  });

  it("serializes public JWK headers and rejects simultaneous jwk and kid", async () => {
    const keyPair = await generateEcP256KeyPair();
    const jwk = await exportPublicJwk(keyPair.publicKey);
    const jws = await signFlattenedJws(keyPair.privateKey, { alg: "ES256", jwk }, null);

    expect(JSON.parse(new TextDecoder().decode(b64uDecode(jws.protected)))).toEqual({ alg: "ES256", jwk });
    await expect(
      signFlattenedJws(keyPair.privateKey, { alg: "ES256", jwk, kid: "account-url" }, null),
    ).rejects.toThrow("both jwk and kid");
  });
});
