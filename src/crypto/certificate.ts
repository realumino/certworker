import "@abraham/reflection";
import * as x509 from "@peculiar/x509";
import { exportPublicJwk, type EcPublicJwk } from "./keys";

const CERTIFICATE_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

export interface CertificateChain {
  certificates: string[];
  leafPem: string;
  chainPem: string;
  fullchainPem: string;
}

export interface ParsedCertificate {
  sans: string[];
  serial: string;
  fingerprintSha256: string;
  notBefore: string;
  notAfter: string;
  publicKeyJwk: EcPublicJwk;
}

export function splitCertificateChain(pem: string): CertificateChain {
  const certificates = [...pem.matchAll(CERTIFICATE_BLOCK)].map(([block]) => `${block.trim()}\n`);
  if (certificates.length === 0 || pem.replace(CERTIFICATE_BLOCK, "").trim().length > 0) {
    throw new TypeError("Expected a PEM certificate chain containing only CERTIFICATE blocks");
  }

  const leafPem = certificates[0];
  const chainPem = certificates.slice(1).join("");
  return {
    certificates,
    leafPem,
    chainPem,
    fullchainPem: `${leafPem}${chainPem}`,
  };
}

export async function parseCertificate(pem: string): Promise<ParsedCertificate> {
  const certificate = new x509.X509Certificate(pem);
  const extension = certificate.getExtension("2.5.29.17");
  if (!(extension instanceof x509.SubjectAlternativeNameExtension)) {
    throw new TypeError("Certificate is missing a Subject Alternative Name extension");
  }

  const sans = extension.names
    .toJSON()
    .filter((name) => name.type === "dns")
    .map((name) => name.value);
  if (sans.length === 0) throw new TypeError("Certificate has no DNS Subject Alternative Names");

  const digest = await crypto.subtle.digest("SHA-256", certificate.rawData);
  const publicKey = await certificate.publicKey.export();

  return {
    sans,
    serial: certificate.serialNumber,
    fingerprintSha256: toHex(new Uint8Array(digest)),
    notBefore: certificate.notBefore.toISOString(),
    notAfter: certificate.notAfter.toISOString(),
    publicKeyJwk: await exportPublicJwk(publicKey),
  };
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
