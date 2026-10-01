import { buildCsr, parseCsr, verifyCsrSignature } from "../src/crypto/csr";
import * as x509 from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import { exportPublicJwk } from "../src/crypto/keys";

async function generateKeyPair(): Promise<CryptoKeyPair> {
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

describe("PKCS#10 CSR", () => {
  it("builds, parses, and verifies a wildcard SAN CSR in workerd", async () => {
    const keyPair = await generateKeyPair();
    const identifiers = ["example.com", "*.example.com"];
    const built = await buildCsr(keyPair, identifiers);
    const parsed = await parseCsr(built.pem);

    expect(built.pem).toMatch(/^-----BEGIN CERTIFICATE REQUEST-----/);
    expect(parsed.sans).toEqual(identifiers);
    expect(parsed.commonName).toBe("example.com");
    expect(parsed.publicKeyJwk).toEqual(await exportPublicJwk(keyPair.publicKey));
    expect(await verifyCsrSignature(built.pem)).toBe(true);

    const parsedFromDer = new x509.Pkcs10CertificateRequest(built.der);
    const sansExtension = parsedFromDer.getExtension("2.5.29.17");
    expect(sansExtension).toBeInstanceOf(x509.SubjectAlternativeNameExtension);
    if (sansExtension instanceof x509.SubjectAlternativeNameExtension) {
      expect(sansExtension.names.toJSON().map((name) => name.value)).toEqual(identifiers);
    }
  });

  it.each([
    [["example.com"]],
    [["example.com", "www.example.com", "api.example.com"]],
  ])("preserves SAN order for %j", async (identifiers) => {
    const built = await buildCsr(await generateKeyPair(), identifiers);
    const parsed = await parseCsr(built.pem);

    expect(parsed.sans).toEqual(identifiers);
    expect(parsed.commonName).toBe(identifiers[0]);
  });

  it("detects a modified CSR signature and rejects an empty identifier list", async () => {
    const built = await buildCsr(await generateKeyPair(), ["example.com"]);
    const tamperedDer = built.der.slice();
    tamperedDer[tamperedDer.length - 1] ^= 1;
    const tamperedPem = new x509.Pkcs10CertificateRequest(tamperedDer).toString();

    await expect(verifyCsrSignature(tamperedPem)).resolves.toBe(false);
    await expect(buildCsr(await generateKeyPair(), [])).rejects.toThrow(
      "at least one non-empty identifier",
    );
  });
});
