import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { AcmeClient, type AcmeAuthorization, type AcmeChallenge, type AcmeIdentifier } from "../src/acme/client";
import { AcmeError } from "../src/acme/errors";
import { dns01RecordName, dns01Value, normalizeDomainName, waitForTxtPropagation } from "../src/acme/dns01";
import { createTxtRecord, deleteTxtRecord, findZoneId } from "../src/dns/cloudflare";
import { parseCertificate, splitCertificateChain } from "../src/crypto/certificate";
import { buildCsr } from "../src/crypto/csr";
import { exportPrivateKeyPem, pemToDer } from "../src/crypto/pem";
import { exportPublicJwk, generateEcP256KeyPair, jwkThumbprint, type EcPublicJwk } from "../src/crypto/keys";

const STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory";
const PRODUCTION_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory";

interface IssueOptions {
  inputDomain: string;
  includeWildcard: boolean;
  directoryUrl: string;
  allowProduction: boolean;
  zoneId?: string;
  accountFile: string;
  outputDirectory: string;
}

interface SavedAccount {
  version: 1;
  directoryUrl: string;
  accountUrl: string;
  privateKeyPem: string;
  publicJwk: EcPublicJwk;
}

interface CreatedRecord {
  zoneId: string;
  recordId: string;
}

function printUsage(): void {
  console.log(`Usage: npm run issue -- <domain> [options]

Options:
  --no-wildcard          Issue only the apex name (wildcard is on by default)
  --zone <zone-id>       Use this Cloudflare zone ID instead of searching for it
  --directory <url>      ACME directory (defaults to Let's Encrypt staging)
  --account-file <path>  Account file (default: .wrangler/acme/account.json)
  --out <path>           Artifact directory (default: .wrangler/acme/out)
  --allow-production     Allow any non-staging ACME directory
  --help                 Show this help`);
}

function parseArguments(args: string[]): IssueOptions | undefined {
  const positionals: string[] = [];
  let includeWildcard = true;
  let allowProduction = false;
  let zoneId: string | undefined;
  let directoryUrl = STAGING_DIRECTORY;
  let accountFile = ".wrangler/acme/account.json";
  let outputDirectory = ".wrangler/acme/out";

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--help" || argument === "-h") return undefined;
    if (argument === "--no-wildcard") {
      includeWildcard = false;
      continue;
    }
    if (argument === "--allow-production") {
      allowProduction = true;
      continue;
    }

    const [flag, inlineValue] = argument.split(/=(.*)/s, 2);
    if (flag === "--zone" || flag === "--directory" || flag === "--account-file" || flag === "--out") {
      const value = inlineValue ?? args[++index];
      if (!value || value.startsWith("--")) throw new TypeError(`Missing value for ${flag}`);
      if (flag === "--zone") zoneId = value;
      if (flag === "--directory") directoryUrl = value;
      if (flag === "--account-file") accountFile = value;
      if (flag === "--out") outputDirectory = value;
      continue;
    }
    if (argument.startsWith("-")) throw new TypeError(`Unknown option: ${argument}`);
    positionals.push(argument);
  }

  if (positionals.length !== 1) return undefined;
  return {
    inputDomain: positionals[0],
    includeWildcard,
    directoryUrl,
    allowProduction,
    zoneId,
    accountFile,
    outputDirectory,
  };
}

async function main(): Promise<void> {
  const options = parseArguments(process.argv.slice(2));
  if (!options) {
    printUsage();
    if (process.argv.slice(2).some((argument) => argument === "--help" || argument === "-h")) return;
    process.exitCode = 2;
    return;
  }

  const identifiers = makeIdentifiers(options.inputDomain, options.includeWildcard);
  const directoryUrl = normalizeDirectoryUrl(options.directoryUrl);
  if (directoryUrl !== STAGING_DIRECTORY && !options.allowProduction) {
    throw new Error("Refusing a non-staging ACME directory without --allow-production");
  }
  if (directoryUrl === PRODUCTION_DIRECTORY && options.allowProduction) {
    console.warn("WARNING: using Let's Encrypt production; this run can issue a publicly trusted certificate.");
  } else if (directoryUrl !== STAGING_DIRECTORY) {
    console.warn(`WARNING: using non-staging ACME directory ${directoryUrl}`);
  }

  const environment = await readEnvironmentFile(resolve(".dev.vars"));
  const apiToken = process.env.CF_DNS_API_TOKEN?.trim() || environment.CF_DNS_API_TOKEN?.trim();
  if (!apiToken) throw new Error("CF_DNS_API_TOKEN is required (set it in .dev.vars or the process environment)");

  const accountFile = resolve(options.accountFile);
  const outputDirectory = resolve(options.outputDirectory);
  const records: CreatedRecord[] = [];
  let issuanceError: unknown;
  let result: Awaited<ReturnType<typeof issueCertificate>> | undefined;

  try {
    result = await issueCertificate({
      identifiers,
      directoryUrl,
      accountFile,
      outputDirectory,
      apiToken,
      zoneId: options.zoneId,
      records,
    });
  } catch (error) {
    issuanceError = error;
  }

  const cleanupFailures: string[] = [];
  for (const record of records) {
    try {
      await deleteTxtRecord({ apiToken, zoneId: record.zoneId, recordId: record.recordId });
    } catch (error) {
      cleanupFailures.push(
        `${record.recordId}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  if (cleanupFailures.length > 0) {
    const cleanupError = new Error(`Could not remove all ACME TXT records: ${cleanupFailures.join("; ")}`);
    if (issuanceError) throw new AggregateError([issuanceError, cleanupError], `${formatError(issuanceError)}; ${cleanupError.message}`);
    throw cleanupError;
  }
  if (issuanceError) throw issuanceError;
  if (!result) throw new Error("Issuance completed without a certificate result");

  console.log(`Issued ${directoryUrl === STAGING_DIRECTORY ? "staging" : "non-staging"} certificate for ${identifiers.map(({ value }) => value).join(", ")}`);
  console.log(`  Serial:      ${result.certificate.serial}`);
  console.log(`  Not after:   ${result.certificate.notAfter}`);
  console.log(`  SANs:        ${result.certificate.sans.join(", ")}`);
  console.log(`  Artifacts:   ${result.outputDirectory}`);
  console.log("  DNS cleanup: all created TXT records removed");
}

async function issueCertificate(input: {
  identifiers: AcmeIdentifier[];
  directoryUrl: string;
  accountFile: string;
  outputDirectory: string;
  apiToken: string;
  zoneId?: string;
  records: CreatedRecord[];
}): Promise<{
  certificate: Awaited<ReturnType<typeof parseCertificate>>;
  outputDirectory: string;
}> {
  const { client, publicJwk } = await loadClient(input.directoryUrl, input.accountFile);
  const thumbprint = await jwkThumbprint(publicJwk);
  const domain = input.identifiers[0].value.replace(/^\*\./, "");
  const zoneId = input.zoneId ?? await findZoneId({ apiToken: input.apiToken, domain });
  const order = await client.newOrder(input.identifiers);
  const pending: Array<{ authorizationUrl: string; challenge: AcmeChallenge; value: string; recordName: string }> = [];

  for (const authorizationUrl of order.authorizations) {
    const authorization = await client.getAuthorization(authorizationUrl);
    if (authorization.status === "valid") continue;
    if (authorization.status === "invalid") throw authorizationError(authorization);

    const challenge = authorization.challenges.find(({ type }) => type === "dns-01");
    if (!challenge) throw new Error(`ACME returned no DNS-01 challenge for ${authorization.identifier.value}`);
    if (challenge.status === "invalid") {
      throw new Error(`DNS-01 challenge for ${authorization.identifier.value} is already invalid`);
    }

    const token = challenge.token;
    if (!token) throw new Error(`DNS-01 challenge for ${authorization.identifier.value} is missing its token`);
    const value = await dns01Value(token, thumbprint);
    pending.push({
      authorizationUrl,
      challenge,
      value,
      recordName: dns01RecordName(authorization.identifier.value),
    });
  }

  const targets = new Map<string, Set<string>>();
  for (const item of pending) {
    if (item.challenge.status === "valid") continue;
    const name = item.recordName;
    const recordId = await createTxtRecord({ apiToken: input.apiToken, zoneId, name, value: item.value, ttl: 60 });
    input.records.push({ zoneId, recordId });
    const values = targets.get(name) ?? new Set<string>();
    values.add(item.value);
    targets.set(name, values);
  }

  if (targets.size > 0) {
    await waitForTxtPropagation(
      [...targets].map(([name, values]) => ({ name, values: [...values] })),
    );
  }

  for (const item of pending) {
    if (item.challenge.status === "pending") await client.acceptChallenge(item.challenge.url);
  }
  for (const item of pending) await client.waitForAuthorizationValid(item.authorizationUrl);

  const readyOrder = await client.waitForOrderReady(order.url);
  const leafKeyPair = await generateEcP256KeyPair();
  const csr = await buildCsr(leafKeyPair, input.identifiers.map(({ value }) => value));
  await client.finalizeOrder(readyOrder.finalize, csr.der, order.url);
  const validOrder = await client.waitForOrderValid(order.url);
  if (!validOrder.certificate) throw new Error("Valid ACME order is missing its certificate URL");

  const downloadedChain = await client.downloadCertificate(validOrder.certificate);
  const chain = splitCertificateChain(downloadedChain);
  const certificate = await parseCertificate(chain.leafPem);
  assertExactSans(certificate.sans, input.identifiers.map(({ value }) => value));

  const leafPublicJwk = certificate.publicKeyJwk;
  const generatedPublicJwk = await exportPublicJwk(leafKeyPair.publicKey);
  if (leafPublicJwk.x !== generatedPublicJwk.x || leafPublicJwk.y !== generatedPublicJwk.y) {
    throw new Error("Issued certificate public key does not match the generated private key");
  }

  const outputDomain = domain.replace(/[^a-z0-9.-]/g, "_");
  const artifactDirectory = join(input.outputDirectory, outputDomain);
  await mkdir(artifactDirectory, { recursive: true });
  const privateKeyPem = await exportPrivateKeyPem(leafKeyPair.privateKey);
  const privateKeyPath = join(artifactDirectory, "privkey.pem");
  const meta = {
    sans: certificate.sans,
    serial: certificate.serial,
    fingerprint_sha256: certificate.fingerprintSha256,
    not_before: certificate.notBefore,
    not_after: certificate.notAfter,
    issued_at: new Date().toISOString(),
    key_type: "ecdsa_p256",
    directory_url: input.directoryUrl,
  };

  await writeFile(join(artifactDirectory, "cert.pem"), chain.leafPem, "utf8");
  await writeFile(join(artifactDirectory, "chain.pem"), chain.chainPem, "utf8");
  await writeFile(join(artifactDirectory, "fullchain.pem"), chain.fullchainPem, "utf8");
  await writeFile(privateKeyPath, privateKeyPem, { encoding: "utf8", mode: 0o600 });
  await chmod(privateKeyPath, 0o600);
  await writeFile(join(artifactDirectory, "meta.json"), `${JSON.stringify(meta, null, 2)}\n`, "utf8");

  return { certificate, outputDirectory: artifactDirectory };
}

async function loadClient(directoryUrl: string, accountFile: string): Promise<{
  client: AcmeClient;
  publicJwk: EcPublicJwk;
}> {
  const saved = await readSavedAccount(accountFile);
  if (saved) {
    if (saved.directoryUrl !== directoryUrl) {
      throw new Error(`Account file ${accountFile} belongs to a different ACME directory`);
    }
    const privateKey = await importPrivateKey(saved.privateKeyPem);
    const publicKey = await importPublicKey(saved.publicJwk);
    const accountKey: CryptoKeyPair = { privateKey, publicKey };
    return {
      client: new AcmeClient({ directoryUrl, accountKey, kid: saved.accountUrl }),
      publicJwk: saved.publicJwk,
    };
  }

  const accountKey = await generateEcP256KeyPair();
  const publicJwk = await exportPublicJwk(accountKey.publicKey);
  const client = new AcmeClient({ directoryUrl, accountKey });
  const accountUrl = await client.ensureAccount();
  const privateKeyPem = await exportPrivateKeyPem(accountKey.privateKey);
  await saveAccount(accountFile, { version: 1, directoryUrl, accountUrl, privateKeyPem, publicJwk });
  return { client, publicJwk };
}

async function readSavedAccount(path: string): Promise<SavedAccount | undefined> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return undefined;
    throw error;
  }

  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`ACME account file ${path} is not valid JSON`);
  }
  if (!isObject(value) || value.version !== 1 || typeof value.directoryUrl !== "string" ||
      typeof value.accountUrl !== "string" || typeof value.privateKeyPem !== "string" ||
      !isPublicJwk(value.publicJwk)) {
    throw new Error(`ACME account file ${path} has an unsupported or incomplete format`);
  }
  return {
    version: 1,
    directoryUrl: value.directoryUrl,
    accountUrl: value.accountUrl,
    privateKeyPem: value.privateKeyPem,
    publicJwk: value.publicJwk,
  };
}

async function saveAccount(path: string, account: SavedAccount): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.new`;
  await writeFile(temporaryPath, `${JSON.stringify(account, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await chmod(temporaryPath, 0o600);
  await rename(temporaryPath, path);
}

async function readEnvironmentFile(path: string): Promise<Record<string, string>> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return {};
    throw error;
  }

  const variables: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!match || match[1].startsWith("#")) continue;
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    variables[match[1]] = value;
  }
  return variables;
}

function makeIdentifiers(input: string, includeWildcard: boolean): AcmeIdentifier[] {
  const normalized = normalizeDomainName(input);
  if (normalized.startsWith("*.")) return [{ type: "dns", value: normalized }];
  const identifiers = [{ type: "dns" as const, value: normalized }];
  if (includeWildcard) identifiers.push({ type: "dns", value: `*.${normalized}` });
  return identifiers;
}

function normalizeDirectoryUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError("ACME directory must be an absolute HTTPS URL");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    throw new TypeError("ACME directory must be an absolute HTTPS URL without credentials or a fragment");
  }
  return url.toString();
}

async function importPrivateKey(pem: string): Promise<CryptoKey> {
  const der = pemToDer(pem, "PRIVATE KEY");
  const keyData = new Uint8Array(new ArrayBuffer(der.byteLength));
  keyData.set(der);
  return crypto.subtle.importKey("pkcs8", keyData, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
}

async function importPublicKey(jwk: EcPublicJwk): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
}

function isPublicJwk(value: unknown): value is EcPublicJwk {
  return isObject(value) && value.kty === "EC" && value.crv === "P-256" &&
    typeof value.x === "string" && typeof value.y === "string";
}

function assertExactSans(actual: string[], expected: string[]): void {
  const actualSet = new Set(actual);
  const expectedSet = new Set(expected);
  if (actualSet.size !== expectedSet.size || expected.some((name) => !actualSet.has(name))) {
    throw new Error(`Issued certificate SAN mismatch: expected [${expected.join(", ")}], received [${actual.join(", ")}]`);
  }
}

function authorizationError(authorization: AcmeAuthorization): AcmeError {
  const problem = authorization.error ?? {
    type: "urn:ietf:params:acme:error:malformed",
    detail: `Authorization for ${authorization.identifier.value} is invalid`,
  };
  return AcmeError.fromProblem(problem, 200);
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

main().catch((error: unknown) => {
  console.error(`ACME issuance failed: ${formatError(error)}`);
  process.exitCode = 1;
});
