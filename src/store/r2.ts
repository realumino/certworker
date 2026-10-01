import type { AcmeEnvironment } from "../issue/types";
import type { EcPublicJwk } from "../crypto/keys";

const R2_PAGE_SIZE = 1000;

export interface AcmeAccountMetadata {
  version: 1;
  directoryUrl: string;
  accountUrl: string;
  publicJwk: EcPublicJwk;
}

export interface CertificateArtifacts {
  certPem: string;
  chainPem: string;
  fullchainPem: string;
  metaJson: string;
}

export function accountMetadataKey(environment: AcmeEnvironment): string {
  return `acme/${environment}/account.json`;
}

export function accountPrivateKeyKey(environment: AcmeEnvironment): string {
  return `acme/${environment}/account-key.pem.enc`;
}

export function certificatePrefix(domainName: string, certificateId: string): string {
  const domain = domainName.replace(/^\*\./, "");
  return `certs/${domain}/${certificateId}`;
}

export function certificatePrivateKeyKey(prefix: string): string {
  return `${prefix}/privkey.pem.enc`;
}

export async function putAcmeAccount(
  bucket: R2Bucket,
  environment: AcmeEnvironment,
  metadata: AcmeAccountMetadata,
  encryptedPrivateKey: Uint8Array,
): Promise<void> {
  await Promise.all([
    bucket.put(accountMetadataKey(environment), `${JSON.stringify(metadata)}\n`),
    bucket.put(accountPrivateKeyKey(environment), encryptedPrivateKey),
  ]);
}

export async function getAcmeAccountMetadata(
  bucket: R2Bucket,
  environment: AcmeEnvironment,
): Promise<AcmeAccountMetadata> {
  const text = await getObjectText(bucket, accountMetadataKey(environment));
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new TypeError(`ACME account metadata for ${environment} is not valid JSON`);
  }
  if (!isAccountMetadata(value)) {
    throw new TypeError(`ACME account metadata for ${environment} has an unsupported format`);
  }
  return value;
}

export async function putCertificatePrivateKey(
  bucket: R2Bucket,
  prefix: string,
  encryptedPrivateKey: Uint8Array,
): Promise<void> {
  await bucket.put(certificatePrivateKeyKey(prefix), encryptedPrivateKey);
}

export async function putCertificateArtifacts(
  bucket: R2Bucket,
  prefix: string,
  artifacts: CertificateArtifacts,
): Promise<void> {
  await Promise.all([
    bucket.put(`${prefix}/cert.pem`, artifacts.certPem),
    bucket.put(`${prefix}/chain.pem`, artifacts.chainPem),
    bucket.put(`${prefix}/fullchain.pem`, artifacts.fullchainPem),
    bucket.put(`${prefix}/meta.json`, artifacts.metaJson),
  ]);
}

export async function getObjectBytes(bucket: R2Bucket, key: string): Promise<Uint8Array> {
  const object = await bucket.get(key);
  if (!object) throw new Error(`R2 object ${key} does not exist`);
  return new Uint8Array(await object.arrayBuffer());
}

export async function getObjectText(bucket: R2Bucket, key: string): Promise<string> {
  const object = await bucket.get(key);
  if (!object) throw new Error(`R2 object ${key} does not exist`);
  return object.text();
}

export async function tryGetObjectText(bucket: R2Bucket, key: string): Promise<string | null> {
  const object = await bucket.get(key);
  if (!object) return null;
  return object.text();
}

export async function tryGetObjectBytes(bucket: R2Bucket, key: string): Promise<Uint8Array | null> {
  const object = await bucket.get(key);
  if (!object) return null;
  return new Uint8Array(await object.arrayBuffer());
}

export async function deletePrefix(bucket: R2Bucket, prefix: string): Promise<void> {
  const normalizedPrefix = prefix.endsWith("/") ? prefix : `${prefix}/`;
  let cursor: string | undefined;

  do {
    const page = await bucket.list({ prefix: normalizedPrefix, cursor, limit: R2_PAGE_SIZE });
    if (page.objects.length > 0) {
      await bucket.delete(page.objects.map(({ key }) => key));
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor !== undefined);
}

function isAccountMetadata(value: unknown): value is AcmeAccountMetadata {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const metadata = value as Record<string, unknown>;
  const jwk = metadata.publicJwk;
  return metadata.version === 1 &&
    typeof metadata.directoryUrl === "string" &&
    typeof metadata.accountUrl === "string" &&
    typeof jwk === "object" && jwk !== null && !Array.isArray(jwk) &&
    (jwk as Record<string, unknown>).kty === "EC" &&
    (jwk as Record<string, unknown>).crv === "P-256" &&
    typeof (jwk as Record<string, unknown>).x === "string" &&
    typeof (jwk as Record<string, unknown>).y === "string";
}
