import { describe, expect, it } from "vitest";
import { b64uDecode, b64uEncode } from "../src/crypto/base64url";

describe("base64url codec", () => {
  it.each([
    ["", ""],
    ["f", "Zg"],
    ["fo", "Zm8"],
    ["foo", "Zm9v"],
    ["foob", "Zm9vYg"],
    ["fooba", "Zm9vYmE"],
    ["foobar", "Zm9vYmFy"],
  ])("encodes and decodes %j", (text, encoded) => {
    const bytes = new TextEncoder().encode(text);
    expect(b64uEncode(bytes)).toBe(encoded);
    expect(new TextDecoder().decode(b64uDecode(encoded))).toBe(text);
  });

  it.each([0, 1, 2, 3, 31, 32, 33, 64])("round-trips %i bytes", (length) => {
    const bytes = Uint8Array.from({ length }, (_, index) => (index * 37) & 0xff);
    expect(b64uDecode(b64uEncode(bytes))).toEqual(bytes);
  });

  it.each(["=", "+", "/", "!", "a"])('rejects invalid input "%s"', (text) => {
    expect(() => b64uDecode(text)).toThrow();
  });

  it.each(["Zh", "Zm9"])('rejects non-canonical trailing bits in "%s"', (text) => {
    expect(() => b64uDecode(text)).toThrow("Non-canonical");
  });
});
