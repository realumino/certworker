import { describe, expect, it } from "vitest";
import {
  decodeEnvelopeSecret,
  decryptEnvelope,
  ENVELOPE_VERSION,
  encryptEnvelope,
  EnvelopeIntegrityError,
  importEnvelopeKey,
} from "../src/crypto/envelope";

const AAD = "certs/example.com/20260101/privkey.pem.enc";

function standardBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function bytes(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (index * 37 + 11) & 0xff);
}

describe("AES-256-GCM envelope", () => {
  it.each([0, 121, 4096])("round-trips %i plaintext bytes", async (length) => {
    const key = await importEnvelopeKey(bytes(32));
    const plaintext = bytes(length);
    const blob = await encryptEnvelope(plaintext, AAD, key);

    expect(blob[0]).toBe(ENVELOPE_VERSION);
    expect(blob.byteLength).toBe(1 + 12 + plaintext.byteLength + 16);
    expect(await decryptEnvelope(blob, AAD, key)).toEqual(plaintext);
  });

  it("uses a fresh IV for each encryption", async () => {
    const key = await importEnvelopeKey(bytes(32));
    const plaintext = bytes(121);
    const first = await encryptEnvelope(plaintext, AAD, key);
    const second = await encryptEnvelope(plaintext, AAD, key);

    expect(first).not.toEqual(second);
    expect(await decryptEnvelope(first, AAD, key)).toEqual(plaintext);
    expect(await decryptEnvelope(second, AAD, key)).toEqual(plaintext);
  });

  it("rejects AAD mismatch, ciphertext tampering, tag tampering, and a wrong key", async () => {
    const key = await importEnvelopeKey(bytes(32));
    const plaintext = bytes(121);
    const blob = await encryptEnvelope(plaintext, AAD, key);
    const changedCiphertext = blob.slice();
    changedCiphertext[13] ^= 1;
    const changedTag = blob.slice();
    changedTag[changedTag.length - 1] ^= 1;

    await expect(decryptEnvelope(blob, `${AAD}.other`, key)).rejects.toBeInstanceOf(
      EnvelopeIntegrityError,
    );
    await expect(decryptEnvelope(changedCiphertext, AAD, key)).rejects.toBeInstanceOf(
      EnvelopeIntegrityError,
    );
    await expect(decryptEnvelope(changedTag, AAD, key)).rejects.toBeInstanceOf(EnvelopeIntegrityError);
    await expect(decryptEnvelope(blob, AAD, await importEnvelopeKey(bytes(32).reverse()))).rejects.toBeInstanceOf(
      EnvelopeIntegrityError,
    );
  });

  it("rejects unsupported versions and truncated blobs", async () => {
    const key = await importEnvelopeKey(bytes(32));
    const blob = await encryptEnvelope(bytes(1), AAD, key);
    const unsupported = blob.slice();
    unsupported[0] = 2;

    await expect(decryptEnvelope(unsupported, AAD, key)).rejects.toThrow("Unsupported envelope version");
    await expect(decryptEnvelope(new Uint8Array(28), AAD, key)).rejects.toThrow("truncated");
  });

  it("decodes exactly 32 bytes from canonical standard base64", async () => {
    const raw = bytes(32);
    const encoded = standardBase64(raw);

    expect(decodeEnvelopeSecret(encoded)).toEqual(raw);
    expect(decodeEnvelopeSecret(` \n${encoded}\r\n `)).toEqual(raw);
    expect(await importEnvelopeKey(raw)).toMatchObject({
      type: "secret",
      extractable: false,
      algorithm: { name: "AES-GCM", length: 256 },
    });
  });

  it("rejects invalid envelope key lengths and encodings", async () => {
    expect(() => decodeEnvelopeSecret(standardBase64(bytes(31)))).toThrow("exactly 32 bytes");
    expect(() => decodeEnvelopeSecret(standardBase64(bytes(33)))).toThrow("exactly 32 bytes");
    expect(() => decodeEnvelopeSecret("not base64")).toThrow("standard base64");
    expect(() => decodeEnvelopeSecret(`${"A".repeat(42)}B=`)).toThrow("canonical");
    await expect(importEnvelopeKey(bytes(16))).rejects.toThrow("exactly 32 bytes");
    await expect(importEnvelopeKey(bytes(31))).rejects.toThrow("exactly 32 bytes");
    await expect(importEnvelopeKey(bytes(33))).rejects.toThrow("exactly 32 bytes");
  });
});
