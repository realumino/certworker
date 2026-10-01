const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const VALUES = new Int16Array(128).fill(-1);

for (let i = 0; i < ALPHABET.length; i += 1) {
  VALUES[ALPHABET.charCodeAt(i)] = i;
}

export function b64uEncode(bytes: Uint8Array): string {
  let result = "";

  for (let i = 0; i < bytes.length; i += 3) {
    const first = bytes[i];
    const hasSecond = i + 1 < bytes.length;
    const hasThird = i + 2 < bytes.length;
    const second = hasSecond ? bytes[i + 1] : 0;
    const third = hasThird ? bytes[i + 2] : 0;

    result += ALPHABET[first >> 2];
    result += ALPHABET[((first & 0x03) << 4) | (second >> 4)];

    if (hasSecond) {
      result += ALPHABET[((second & 0x0f) << 2) | (third >> 6)];
    }
    if (hasThird) {
      result += ALPHABET[third & 0x3f];
    }
  }

  return result;
}

export function b64uDecode(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    throw new TypeError("Invalid unpadded base64url string");
  }

  const remainder = text.length % 4;
  if (remainder === 2 && (VALUES[text.charCodeAt(text.length - 1)] & 0x0f) !== 0) {
    throw new TypeError("Non-canonical base64url string");
  }
  if (remainder === 3 && (VALUES[text.charCodeAt(text.length - 1)] & 0x03) !== 0) {
    throw new TypeError("Non-canonical base64url string");
  }

  const output = new Uint8Array(Math.floor((text.length * 3) / 4));
  let accumulator = 0;
  let bitCount = 0;
  let outputIndex = 0;

  for (let i = 0; i < text.length; i += 1) {
    accumulator = (accumulator << 6) | VALUES[text.charCodeAt(i)];
    bitCount += 6;

    if (bitCount >= 8) {
      bitCount -= 8;
      output[outputIndex] = (accumulator >> bitCount) & 0xff;
      outputIndex += 1;
      accumulator &= (1 << bitCount) - 1;
    }
  }

  return output;
}
