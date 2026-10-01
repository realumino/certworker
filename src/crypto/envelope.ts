export const ENVELOPE_VERSION = 1;

const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const HEADER_LENGTH = 1 + IV_LENGTH;
const MIN_ENVELOPE_LENGTH = HEADER_LENGTH + TAG_LENGTH;
const KEY_LENGTH = 32;

/**
 * Envelope bytes are version (0x01) || 12-byte IV || ciphertext || 16-byte GCM tag.
 * Callers bind each ciphertext to its exact R2 object path via `aad`; later key
 * rotation can use a new envelope version.
 */
export class EnvelopeIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvelopeIntegrityError";
  }
}

/** Decode a standard-base64 ENVELOPE_KEY containing exactly 32 random bytes. */
export function decodeEnvelopeSecret(encoded: string): Uint8Array {
  const normalized = encoded.replace(/\s/g, "");

  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(normalized)) {
    throw new TypeError("ENVELOPE_KEY must be standard base64");
  }

  let binary: string;
  try {
    binary = atob(normalized);
  } catch {
    throw new TypeError("ENVELOPE_KEY must be standard base64");
  }

  const raw = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (raw.byteLength !== KEY_LENGTH) {
    throw new TypeError("ENVELOPE_KEY must decode to exactly 32 bytes");
  }

  let canonical = "";
  for (const byte of raw) canonical += String.fromCharCode(byte);
  if (btoa(canonical) !== normalized) {
    throw new TypeError("ENVELOPE_KEY must use canonical standard base64");
  }

  return raw;
}

export async function importEnvelopeKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.byteLength !== KEY_LENGTH) {
    throw new TypeError("Envelope key must be exactly 32 bytes");
  }

  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptEnvelope(
  plaintext: Uint8Array,
  aad: string,
  key: CryptoKey,
): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertextAndTag = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: new TextEncoder().encode(aad),
      tagLength: TAG_LENGTH * 8,
    },
    key,
    plaintext,
  );
  const result = new Uint8Array(HEADER_LENGTH + ciphertextAndTag.byteLength);
  result[0] = ENVELOPE_VERSION;
  result.set(iv, 1);
  result.set(new Uint8Array(ciphertextAndTag), HEADER_LENGTH);

  return result;
}

export async function decryptEnvelope(
  blob: Uint8Array,
  aad: string,
  key: CryptoKey,
): Promise<Uint8Array> {
  if (blob.byteLength < MIN_ENVELOPE_LENGTH) {
    throw new EnvelopeIntegrityError("Envelope is truncated");
  }
  if (blob[0] !== ENVELOPE_VERSION) {
    throw new EnvelopeIntegrityError(`Unsupported envelope version: ${blob[0]}`);
  }

  const iv = blob.slice(1, HEADER_LENGTH);
  const ciphertextAndTag = blob.slice(HEADER_LENGTH);

  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: new TextEncoder().encode(aad),
        tagLength: TAG_LENGTH * 8,
      },
      key,
      ciphertextAndTag,
    );
    return new Uint8Array(plaintext);
  } catch {
    throw new EnvelopeIntegrityError("Envelope authentication failed");
  }
}
