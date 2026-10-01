import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { decryptEnvelope, decodeEnvelopeSecret, importEnvelopeKey } from "../src/crypto/envelope";
import {
  accountMetadataKey,
  accountPrivateKeyKey,
  certificatePrefix,
  deletePrefix,
  getAcmeAccountMetadata,
  getObjectBytes,
  getObjectText,
  putAcmeAccount,
  putCertificateArtifacts,
  putCertificatePrivateKey,
} from "../src/store/r2";

describe("R2 artifact storage", () => {
  it("writes account and certificate artifacts at the designed keys", async () => {
    const environment = "staging";
    const account = {
      version: 1 as const,
      directoryUrl: "https://acme-staging-v02.api.letsencrypt.org/directory",
      accountUrl: `https://acme.example/account/${crypto.randomUUID()}`,
      publicJwk: { kty: "EC" as const, crv: "P-256" as const, x: "abc", y: "def" },
    };
    const accountKey = new Uint8Array([1, 2, 3, 4]);
    await putAcmeAccount(env.CERTS, environment, account, accountKey);

    expect(await getAcmeAccountMetadata(env.CERTS, environment)).toEqual(account);
    expect([...await getObjectBytes(env.CERTS, accountPrivateKeyKey(environment))]).toEqual([...accountKey]);
    expect(accountMetadataKey(environment)).toBe("acme/staging/account.json");

    const prefix = certificatePrefix("*.example.com", crypto.randomUUID());
    await putCertificatePrivateKey(env.CERTS, prefix, new Uint8Array([9, 8, 7]));
    await putCertificateArtifacts(env.CERTS, prefix, {
      certPem: "leaf pem",
      chainPem: "chain pem",
      fullchainPem: "fullchain pem",
      metaJson: '{"key_type":"ecdsa_p256"}',
    });
    expect(await getObjectText(env.CERTS, `${prefix}/cert.pem`)).toBe("leaf pem");
    expect(await getObjectText(env.CERTS, `${prefix}/chain.pem`)).toBe("chain pem");
    expect(await getObjectText(env.CERTS, `${prefix}/fullchain.pem`)).toBe("fullchain pem");
    expect(await getObjectText(env.CERTS, `${prefix}/meta.json`)).toContain("ecdsa_p256");
  });

  it("decrypts only with the object path used as AAD", async () => {
    const prefix = certificatePrefix("example.com", crypto.randomUUID());
    const keyPath = `${prefix}/privkey.pem.enc`;
    const key = await importEnvelopeKey(decodeEnvelopeSecret(env.ENVELOPE_KEY));
    const plaintext = new TextEncoder().encode("private key test bytes");
    const { encryptEnvelope } = await import("../src/crypto/envelope");
    const encrypted = await encryptEnvelope(plaintext, keyPath, key);
    await putCertificatePrivateKey(env.CERTS, prefix, encrypted);

    expect(new TextDecoder().decode(await decryptEnvelope(await getObjectBytes(env.CERTS, keyPath), keyPath, key)))
      .toBe("private key test bytes");
    await expect(decryptEnvelope(await getObjectBytes(env.CERTS, keyPath), `${keyPath}.other`, key))
      .rejects.toThrow("Envelope authentication failed");
  });

  it("deletes paginated prefixes without touching sibling paths", async () => {
    const prefix = `certs/delete-test/${crypto.randomUUID()}`;
    for (let index = 0; index < 1001; index += 1) {
      await env.CERTS.put(`${prefix}/object-${index.toString().padStart(4, "0")}`, "x");
    }
    await env.CERTS.put(`${prefix}-sibling/object.txt`, "keep");

    await deletePrefix(env.CERTS, prefix);

    expect((await env.CERTS.list({ prefix: `${prefix}/` })).objects).toHaveLength(0);
    expect(await getObjectText(env.CERTS, `${prefix}-sibling/object.txt`)).toBe("keep");
  }, 15_000);
});
