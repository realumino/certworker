import { describe, expect, it } from "vitest";
import { b64uDecode } from "../src/crypto/base64url";
import { exportPublicJwk, generateEcP256KeyPair, jwkThumbprint } from "../src/crypto/keys";

const RFC_7638_RSA_JWK = {
  kty: "RSA",
  e: "AQAB",
  n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  alg: "RS256",
  kid: "2011-04-29",
};

describe("EC P-256 keys and JWK thumbprints", () => {
  it("generates a sign/verify key pair", async () => {
    const keyPair = await generateEcP256KeyPair();
    const message = new TextEncoder().encode("key-pair round trip");
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      keyPair.privateKey,
      message,
    );

    expect(keyPair.privateKey.algorithm).toMatchObject({ name: "ECDSA", namedCurve: "P-256" });
    expect(keyPair.privateKey.extractable).toBe(true);
    expect(
      await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        keyPair.publicKey,
        signature,
        message,
      ),
    ).toBe(true);
  });

  it("exports only the required EC public JWK members", async () => {
    const keyPair = await generateEcP256KeyPair();
    const jwk = await exportPublicJwk(keyPair.publicKey);

    expect(jwk).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(jwk.x).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(jwk.y).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const imported = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const message = new TextEncoder().encode("public JWK import");
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      keyPair.privateKey,
      message,
    );

    expect(
      await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        imported,
        signature,
        message,
      ),
    ).toBe(true);
  });

  it("matches RFC 7638 section 3.1 and ignores optional JWK members", async () => {
    await expect(jwkThumbprint(RFC_7638_RSA_JWK)).resolves.toBe(
      "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
    );
  });

  it("returns a stable public-key thumbprint that ignores private members", async () => {
    const keyPair = await generateEcP256KeyPair();
    const publicJwk = await exportPublicJwk(keyPair.publicKey);
    const exportedPrivateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

    if (exportedPrivateJwk instanceof ArrayBuffer) {
      throw new TypeError("Web Crypto did not export a private JWK");
    }

    const thumbprint = await jwkThumbprint(publicJwk);
    expect(thumbprint).toMatch(/^[A-Za-z0-9_-]{43}$/);
    await expect(jwkThumbprint(publicJwk)).resolves.toBe(thumbprint);
    await expect(jwkThumbprint(exportedPrivateJwk)).resolves.toBe(thumbprint);

    const otherKeyPair = await generateEcP256KeyPair();
    await expect(jwkThumbprint(await exportPublicJwk(otherKeyPair.publicKey))).resolves.not.toBe(
      thumbprint,
    );
  });

  it("rejects unsupported or incomplete JWKs", async () => {
    await expect(jwkThumbprint({ kty: "OKP" })).rejects.toThrow(RangeError);
    await expect(jwkThumbprint({ kty: "EC", crv: "P-256", x: "only-one-coordinate" })).rejects.toThrow(
      "missing required member: y",
    );
    expect(b64uDecode((await exportPublicJwk((await generateEcP256KeyPair()).publicKey)).x)).toHaveLength(32);
  });
});
