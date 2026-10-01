import "@abraham/reflection";
import * as x509 from "@peculiar/x509";
import { exportPublicJwk, type EcPublicJwk } from "./keys";

export interface BuiltCsr {
  pem: string;
  der: Uint8Array;
}

export interface ParsedCsr {
  sans: string[];
  commonName: string;
  publicKeyJwk: EcPublicJwk;
}

function parseRequest(pem: string): x509.Pkcs10CertificateRequest {
  return new x509.Pkcs10CertificateRequest(pem);
}

export async function buildCsr(
  keyPair: CryptoKeyPair,
  identifiers: string[],
): Promise<BuiltCsr> {
  if (identifiers.length === 0 || identifiers.some((identifier) => identifier.length === 0)) {
    throw new TypeError("A CSR requires at least one non-empty identifier");
  }

  const request = await x509.Pkcs10CertificateRequestGenerator.create({
    name: [{ CN: [identifiers[0]] }],
    keys: keyPair,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: [
      new x509.SubjectAlternativeNameExtension(
        identifiers.map((value) => ({ type: "dns" as const, value })),
        false,
      ),
    ],
  });

  return {
    pem: request.toString(),
    der: new Uint8Array(request.rawData),
  };
}

export async function parseCsr(pem: string): Promise<ParsedCsr> {
  const request = parseRequest(pem);
  const extension = request.getExtension("2.5.29.17");

  if (!(extension instanceof x509.SubjectAlternativeNameExtension)) {
    throw new TypeError("CSR is missing a Subject Alternative Name extension");
  }

  const sans = extension.names
    .toJSON()
    .filter((name) => name.type === "dns")
    .map((name) => name.value);
  const commonName = request.subjectName.getField("CN")[0];

  if (commonName === undefined) {
    throw new TypeError("CSR is missing a common name");
  }

  const publicKey = await request.publicKey.export();

  return {
    sans,
    commonName,
    publicKeyJwk: await exportPublicJwk(publicKey),
  };
}

export async function verifyCsrSignature(pem: string): Promise<boolean> {
  return parseRequest(pem).verify();
}
