type AlgoOptions =
  | Omit<RsaOaepParams, "name">
  | Omit<AesCtrParams, "name">
  | Omit<AesCbcParams, "name">
  | Omit<AesGcmParams, "name">;

/**
 * Encrypts the given data using the given key and options.
 *
 * @param data - The data to encrypt. Can be a string or an ArrayBuffer.
 * @param key - The key to use for encryption. Must be a CryptoKey with the
 * 'encrypt' usage.
 * @param options - Options to pass to the underlying SubtleCrypto.encrypt
 * function. Can include the algorithm parameters and any other options
 * supported by the underlying algorithm.
 *
 * @returns A promise that resolves to the encrypted data as an ArrayBuffer.
 *
 * @throws Error - If the key does not support encryption or if the algorithm
 * is not supported.
 */
export function encrypt(
  data: string | ArrayBuffer,
  key: CryptoKey,
  options?: AlgoOptions,
): Promise<ArrayBuffer> {
  const algorithm = { ...key.algorithm, ...options };
  const allowedAlgorithms = ["RSA-OAEP", "AES-CTR", "AES-CBC", "AES-GCM"];
  if (!allowedAlgorithms.includes(key.algorithm.name)) {
    throw new Error("Unsupported algorithm");
  } else if (!key.usages.includes("encrypt")) {
    throw new Error("Key does not support encryption");
  }
  return crypto.subtle.encrypt(
    algorithm,
    key,
    data instanceof ArrayBuffer ? data : new TextEncoder().encode(data),
  );
}

/**
 * Decrypts the given data using the given key and options.
 *
 * @param data - The data to decrypt. Can be a string or an ArrayBuffer.
 * @param key - The key to use for decryption. Must be a CryptoKey with the
 * 'decrypt' usage.
 * @param options - Options to pass to the underlying SubtleCrypto.decrypt
 * function. Can include the algorithm parameters and any other options
 * supported by the underlying algorithm.
 *
 * @returns A promise that resolves to the decrypted data as an ArrayBuffer.
 *
 * @throws Error - If the key does not support decryption or if the algorithm
 * is not supported.
 */
export function decrypt(
  data: string | ArrayBuffer,
  key: CryptoKey,
  options?: AlgoOptions,
): Promise<ArrayBuffer> {
  const algorithm = { ...key.algorithm, ...options };
  const allowedAlgorithms = ["RSA-OAEP", "AES-CTR", "AES-CBC", "AES-GCM"];
  if (!allowedAlgorithms.includes(key.algorithm.name)) {
    throw new Error("Unsupported algorithm");
  } else if (!key.usages.includes("decrypt")) {
    throw new Error("Key does not support decryption");
  }
  return crypto.subtle.decrypt(
    algorithm,
    key,
    data instanceof ArrayBuffer ? data : new TextEncoder().encode(data),
  );
}
