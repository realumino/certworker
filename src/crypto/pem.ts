const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function derToPem(der: Uint8Array, label: string): string {
  if (!/^[A-Z0-9 ]+$/.test(label)) throw new TypeError("PEM label contains invalid characters");
  if (der.byteLength === 0) throw new TypeError("Cannot encode an empty DER value as PEM");

  const base64 = bytesToBase64(der);
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

export function pemToDer(pem: string, label: string): Uint8Array {
  if (!/^[A-Z0-9 ]+$/.test(label)) throw new TypeError("PEM label contains invalid characters");
  const trimmed = pem.trim();
  const begin = `-----BEGIN ${label}-----`;
  const end = `-----END ${label}-----`;
  if (!trimmed.startsWith(begin) || !trimmed.endsWith(end)) throw new TypeError(`Expected a ${label} PEM block`);

  const base64 = trimmed.slice(begin.length, -end.length).replace(/\s/g, "");
  if (
    base64.length === 0 ||
    base64.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64)
  ) {
    throw new TypeError(`Invalid base64 in ${label} PEM block`);
  }

  const binary = atob(base64);
  const result = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytesToBase64(result) !== base64) throw new TypeError(`Non-canonical base64 in ${label} PEM block`);
  return result;
}

export async function exportPrivateKeyPem(privateKey: CryptoKey): Promise<string> {
  if (privateKey.type !== "private") throw new TypeError("Expected a private key");
  const der = await crypto.subtle.exportKey("pkcs8", privateKey);
  if (!(der instanceof ArrayBuffer)) throw new TypeError("Web Crypto did not export a PKCS#8 key");
  return derToPem(new Uint8Array(der), "PRIVATE KEY");
}

export async function importPrivateKeyPem(pem: string): Promise<CryptoKey> {
  const der = pemToDer(pem, "PRIVATE KEY");
  const keyData = new Uint8Array(new ArrayBuffer(der.byteLength));
  keyData.set(der);
  return crypto.subtle.importKey(
    "pkcs8",
    keyData,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
