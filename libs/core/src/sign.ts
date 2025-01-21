type AlgoOptions =
  | Omit<RsaPssParams, "name">
  | Omit<EcdsaParams, "name">;

/**
 * Signs the given data using the specified key and options.
 *
 * The signature is generated using an algorithm specified in the options,
 * which must be supported by the key. Supported algorithms include RSA-PSS,
 * ECDSA, HMAC, and Ed25519.
 *
 * @param data - The data to sign, either as a string or an ArrayBuffer.
 * @param key - The CryptoKey to use for signing, which must have the 'sign' usage.
 * @param options - Optional parameters for the signing algorithm.
 *
 * @returns A promise that resolves to the signature as an ArrayBuffer.
 *
 * @throws Error - If the algorithm is not supported or the key does not have
 * the 'sign' usage.
 */
export function sign(
  data: string | ArrayBuffer,
  key: CryptoKey,
  options?: AlgoOptions,
): Promise<ArrayBuffer> {
  const algorithm = { ...key.algorithm, ...options };
  const allowedAlgorithms = ["RSA-PSS", "ECDSA", "HMAC", "Ed25519"];
  if (!allowedAlgorithms.includes(key.algorithm.name)) {
    throw new Error("Unsupported algorithm");
  } else if (!key.usages.includes("sign")) {
    throw new Error("Key does not support signing");
  }
  return crypto.subtle.sign(
    algorithm,
    key,
    data instanceof ArrayBuffer ? data : new TextEncoder().encode(data),
  );
}

/**
 * Verifies the given signature for the given data using the specified key and options.
 *
 * The signature is verified using an algorithm specified in the options,
 * which must be supported by the key. Supported algorithms include RSA-PSS,
 * ECDSA, HMAC, and Ed25519.
 *
 * @param data - The data to verify, either as a string or an ArrayBuffer.
 * @param key - The CryptoKey to use for verifying, which must have the 'verify' usage.
 * @param signature - The signature to verify, as an ArrayBuffer.
 * @param options - Optional parameters for the verifying algorithm.
 *
 * @returns A promise that resolves to a boolean indicating whether the signature is valid.
 *
 * @throws Error - If the algorithm is not supported or the key does not have
 * the 'verify' usage.
 */
export function verify(
  data: string | ArrayBuffer,
  key: CryptoKey,
  signature: ArrayBuffer,
  options?: AlgoOptions,
): Promise<boolean> {
  const algorithm = { ...key.algorithm, ...options };
  const allowedAlgorithms = ["RSA-PSS", "ECDSA", "HMAC", "Ed25519"];
  if (!allowedAlgorithms.includes(key.algorithm.name)) {
    throw new Error("Unsupported algorithm");
  } else if (!key.usages.includes("verify")) {
    throw new Error("Key does not support verifying");
  }
  return crypto.subtle.verify(
    algorithm,
    key,
    signature,
    data instanceof ArrayBuffer ? data : new TextEncoder().encode(data),
  );
}
