import type { AlgoOptions, KeyGenParams } from "./generate.ts";

/**
 * Exports a key in the specified format.
 *
 * @param format - The format to export the key in. One of "jwk", "raw", "spki", or
 * "pkcs8".
 * @param key - The key to export.
 * @returns A promise that resolves to the exported key. If the format is "jwk",
 * the key will be resolved as a JsonWebKey. Otherwise, the key will be resolved
 * as an ArrayBuffer.
 *
 * @throws Error - If the key does not support exporting.
 */
export function exportKey<T extends KeyFormat>(
  format: T,
  key: CryptoKey,
): Promise<T extends "jwk" ? JsonWebKey : ArrayBuffer> {
  if (!key.extractable) {
    throw new Error("Key does not support exporting");
  }
  if (format === "jwk") {
    return crypto.subtle.exportKey("jwk", key) as ReturnType<
      typeof exportKey<T>
    >;
  } else {
    return crypto.subtle.exportKey(format, key) as ReturnType<
      typeof exportKey<T>
    >;
  }
}

/**
 * Imports a key in the specified format.
 *
 * @param format - The format to import the key in. One of "jwk", "raw", "spki", or
 * "pkcs8".
 * @param type - The type of the key. One of "public" or "private".
 * @param key - The key to import. If the format is "jwk", this is a JsonWebKey.
 * Otherwise, it is an ArrayBuffer.
 * @param options - The options to use for importing the key. Must include the
 * algorithm to use.
 * @param extractable - Whether the key should be extractable. Defaults to the
 * value in the options.
 *
 * @returns A promise that resolves to the imported key as a CryptoKey.
 *
 * @throws Error - If the key cannot be imported.
 */
export function importKey<T extends AlgoOptions, F extends KeyFormat>(
  format: F,
  type: KeyType,
  key: F extends "jwk" ? JsonWebKey : ArrayBuffer,
  options: KeyGenParams<T>,
  extractable?: boolean,
): Promise<CryptoKey> {
  const keyUsages = options.keyUsages.filter((usage) => {
    if (
      type === "public" &&
      (usage === "sign" || usage === "unwrapKey" || usage === "decrypt")
    ) {
      return false;
    }
    if (
      type === "private" &&
      (usage === "verify" || usage === "wrapKey" || usage === "encrypt")
    ) {
      return false;
    }
    return true;
  });
  if (format === "jwk") {
    return crypto.subtle.importKey(
      format,
      key as JsonWebKey,
      options.algorithm,
      extractable !== undefined ? extractable : options.extractable,
      keyUsages,
    );
  } else {
    return crypto.subtle.importKey(
      format,
      key as ArrayBuffer,
      options.algorithm,
      extractable !== undefined ? extractable : options.extractable,
      keyUsages,
    );
  }
}
