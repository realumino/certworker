import "@abraham/reflection";
import * as x509 from "@peculiar/x509";
import { describe, expect, it } from "vitest";
import { parseCertificate, splitCertificateChain } from "../src/crypto/certificate";
import { exportPublicJwk, generateEcP256KeyPair } from "../src/crypto/keys";

describe("X.509 certificate parsing", () => {
  it("splits and parses a leaf-plus-chain PEM bundle", async () => {
    const keyPair = await generateEcP256KeyPair();
    const cert = await makeCertificate(keyPair);
    const pem = cert.toString();
    const chain = splitCertificateChain(`${pem}\n${pem}`);
    const parsed = await parseCertificate(chain.leafPem);

    expect(chain.certificates).toHaveLength(2);
    expect(chain.chainPem).toContain("BEGIN CERTIFICATE");
    expect(chain.fullchainPem).toBe(`${chain.leafPem}${chain.chainPem}`);
    expect(parsed.sans).toEqual(["example.com", "*.example.com"]);
    expect(parsed.serial).toBe(cert.serialNumber);
    expect(parsed.notBefore).toBe(cert.notBefore.toISOString());
    expect(parsed.notAfter).toBe(cert.notAfter.toISOString());
    expect(parsed.fingerprintSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(parsed.publicKeyJwk).toEqual(await exportPublicJwk(keyPair.publicKey));
  });

  it("rejects non-PEM chains and certificates without DNS SANs", async () => {
    expect(() => splitCertificateChain("not a certificate")).toThrow("PEM certificate chain");
    const keyPair = await generateEcP256KeyPair();
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      name: "CN=example.com",
      keys: keyPair,
      notBefore: new Date("2026-01-01T00:00:00Z"),
      notAfter: new Date("2027-01-01T00:00:00Z"),
    });
    await expect(parseCertificate(cert.toString())).rejects.toThrow("Subject Alternative Name");
  });
});

async function makeCertificate(keyPair: CryptoKeyPair): Promise<x509.X509Certificate> {
  return x509.X509CertificateGenerator.createSelfSigned({
    name: "CN=example.com",
    keys: keyPair,
    notBefore: new Date("2026-01-01T00:00:00Z"),
    notAfter: new Date("2027-01-01T00:00:00Z"),
    extensions: [
      new x509.SubjectAlternativeNameExtension(
        [
          { type: "dns", value: "example.com" },
          { type: "dns", value: "*.example.com" },
        ],
        false,
      ),
    ],
  });
}
