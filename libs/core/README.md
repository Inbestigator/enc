# Enc core

Enc abstracts the complexity of the WebCrypto API, allowing you to implement
secure cryptographic operations with minimal effort and code.

The core Enc library contains the primitives for generating keys,
encryption/decryption, signing/verifying, exporting and importing.

## Getting started

```ts
import { decrypt, encrypt, generateKey, rsaKey } from "@enc/core";

const keys = await generateKey(rsaKey("Encrypting"));
const encryptedData = await encrypt("Hello World!", keys.publicKey);
const decryptedData = await decrypt(encryptedData, keys.privateKey);
console.log(decryptedData);
```
