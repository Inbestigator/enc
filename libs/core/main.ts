import {
  decrypt,
  encrypt,
  exportKey,
  generateKey,
  importKey,
  rsaKey,
  sign,
  verify,
} from "@enc/core";

const encKeys = await generateKey(rsaKey("Encrypting"));
const sigKeys = await generateKey(rsaKey("Signing"));

const encryptedData = await encrypt("Hello World!", encKeys.publicKey);
const decryptedData = await decrypt(encryptedData, encKeys.privateKey);

const signature = await sign(decryptedData, sigKeys.privateKey, {
  saltLength: 32,
});

const exportedKey = await exportKey("spki", sigKeys.publicKey);
const importedKey = await importKey(
  "spki",
  "public",
  exportedKey,
  rsaKey("Signing"),
);

const isValid = await verify(decryptedData, importedKey, signature, {
  saltLength: 32,
});

console.log(isValid);
