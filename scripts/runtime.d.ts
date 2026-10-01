import type { webcrypto } from "node:crypto";

declare global {
  type CryptoKeyPair = webcrypto.CryptoKeyPair;
  type JsonWebKey = webcrypto.JsonWebKey;
}

export {};
