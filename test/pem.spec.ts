import { describe, expect, it } from "vitest";
import { exportPrivateKeyPem, importPrivateKeyPem, pemToDer, derToPem } from "../src/crypto/pem";
import { generateEcP256KeyPair } from "../src/crypto/keys";

describe("PEM helpers", () => {
  it("round-trips DER bytes with PEM armor", () => {
    const der = Uint8Array.from([0, 1, 2, 127, 128, 254, 255]);
    const pem = derToPem(der, "CERTIFICATE");
    expect(pem).toContain("-----BEGIN CERTIFICATE-----");
    expect(pemToDer(pem, "CERTIFICATE")).toEqual(der);
  });

  it("exports and reimports an ECDSA PKCS#8 private key", async () => {
    const pair = await generateEcP256KeyPair();
    const pem = await exportPrivateKeyPem(pair.privateKey);
    const imported = await importPrivateKeyPem(pem);
    const data = new TextEncoder().encode("private key PEM round trip");
    const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, imported, data);
    await expect(
      crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pair.publicKey, signature, data),
    ).resolves.toBe(true);
    expect(imported.extractable).toBe(false);
  });

  it("rejects the wrong PEM label and invalid base64", () => {
    const certificate = derToPem(Uint8Array.of(1, 2, 3), "CERTIFICATE");
    expect(() => pemToDer(certificate, "PRIVATE KEY")).toThrow("Expected a PRIVATE KEY");
    expect(() => pemToDer("-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----", "CERTIFICATE"))
      .toThrow("Invalid base64");
  });
});
