export type AlgoOptions =
  | RsaHashedKeyGenParams
  | EcKeyGenParams
  | AesKeyGenParams
  | HmacKeyGenParams
  | AlgorithmIdentifier;

export interface KeyGenParams<T extends AlgoOptions> {
  algorithm: T;
  extractable: boolean;
  keyUsages: KeyUsage[];
}

/**
 * Generates a new key or key pair using the given algorithm and options.
 *
 * If the `algorithm` is an {@link RsaHashedKeyGenParams} or
 * {@link EcKeyGenParams}, the promise resolves to a {@link CryptoKeyPair}. If
 * the `algorithm` is an {@link AlgorithmIdentifier}, the promise resolves to a
 * {@link CryptoKeyPair} or a {@link CryptoKey} depending on the `extractable`
 * option. If the `algorithm` is none of the above, the promise resolves to a
 * {@link CryptoKey}.
 *
 * @param options - The options to use for generating the key.
 * @param extractable - Whether the key should be extractable. Defaults to the value in the options.
 * @returns A promise that resolves to the generated key or key pair.
 */
export function generateKey<T extends AlgoOptions>(
  options: KeyGenParams<T>,
  extractable?: boolean,
): Promise<
  T extends RsaHashedKeyGenParams | EcKeyGenParams ? CryptoKeyPair
    : CryptoKey
> {
  return crypto.subtle.generateKey(
    options.algorithm,
    extractable !== undefined ? extractable : options.extractable,
    options.keyUsages,
  ) as ReturnType<typeof generateKey<T>>;
}

/**
 * Generates options for generating/importing a key pair using the EC algorithm.
 *
 * @param purpose - The purpose of the key pair.
 * @param curve - The curve to use. Defaults to "P-256".
 * @returns The options to use with the generateKey/importKey function.
 */
export function ecKey(
  purpose: "Signing" | "Encrypting",
  curve: "P-256" | "P-384" | "P-521" = "P-256",
): KeyGenParams<EcKeyGenParams> {
  return {
    algorithm: {
      name: purpose === "Signing" ? "ECDSA" : "ECDH",
      namedCurve: curve,
    },
    extractable: true,
    keyUsages: purpose === "Signing"
      ? ["sign", "verify"]
      : ["deriveKey", "deriveBits"],
  };
}

/**
 * Generates options for generating/importing a key pair using the RSA algorithm.
 *
 * @param purpose - The purpose of the key pair, either "Signing" or "Encrypting".
 * @param length - The modulus length in bits. Defaults to 2048.
 * @param hash - The hash algorithm to use. Defaults to "SHA-256".
 * @returns The options to use with the generateKey/importKey function.
 */
export function rsaKey(
  purpose: "Signing" | "Encrypting",
  length = 2048,
  hash: "SHA-256" | "SHA-384" | "SHA-512" = "SHA-256",
): KeyGenParams<RsaHashedKeyGenParams> {
  return {
    algorithm: {
      name: purpose === "Signing" ? "RSA-PSS" : "RSA-OAEP",
      hash,
      modulusLength: length,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    },
    extractable: true,
    keyUsages: purpose === "Signing"
      ? ["sign", "verify"]
      : ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
  };
}

/**
 * Generates options for generating/importing a key pair using the HMAC algorithm.
 *
 * @param hash - The hash algorithm to use. Defaults to "SHA-256".
 * @param length - The length of the key in bits. If not specified, the key
 * length will depend on the hash algorithm.
 * @returns The options to use with the generateKey/importKey function.
 */
export function hmacKey(
  hash: "SHA-256" | "SHA-384" | "SHA-512" = "SHA-256",
  length?: number,
): KeyGenParams<HmacKeyGenParams> {
  return {
    algorithm: {
      name: "HMAC",
      hash,
      length,
    },
    extractable: true,
    keyUsages: ["sign", "verify"],
  };
}

/**
 * Generates options for generating/importing a key pair using the AES algorithm.
 *
 * @param purpose - The purpose of the key pair. One of "Wrapping", "Fixed length encryption", "Variable length encryption", or "Integrity protection".
 * @param length - The length of the key in bits. Defaults to 256.
 * @returns The options to use with the generateKey/importKey function.
 */
export function aesKey(
  purpose:
    | "Wrapping"
    | "Fixed length encryption"
    | "Variable length encryption"
    | "Integrity protection",
  length: 128 | 192 | 256 = 256,
): KeyGenParams<AesKeyGenParams> {
  return {
    algorithm: {
      name: purpose === "Wrapping"
        ? "AES-KW"
        : purpose === "Integrity protection"
        ? "AES-GCM"
        : purpose === "Fixed length encryption"
        ? "AES-CBC"
        : "AES-CTR",
      length,
    },
    extractable: true,
    keyUsages: purpose === "Wrapping"
      ? ["wrapKey", "unwrapKey"]
      : ["encrypt", "decrypt"],
  };
}

/**
 * Generates options for generating/importing a key pair using the Ed25519 algorithm.
 *
 * @returns The options to use with the generateKey/importKey function.
 */
export function edKey(): KeyGenParams<Algorithm> {
  return {
    algorithm: {
      name: "Ed25519",
    },
    extractable: true,
    keyUsages: ["sign", "verify"],
  };
}

/**
 * Generates options for generating/importing a key pair using the X25519 algorithm.
 *
 * @returns The options to use with the generateKey/importKey function.
 */
export function xKey(): KeyGenParams<Algorithm> {
  return {
    algorithm: {
      name: "X25519",
    },
    extractable: true,
    keyUsages: ["deriveKey", "deriveBits"],
  };
}
