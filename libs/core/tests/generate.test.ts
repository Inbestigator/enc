import {
  aesKey,
  ecKey,
  edKey,
  generateKey,
  hmacKey,
  rsaKey,
  xKey,
} from "@enc/core";

Deno.test("generateKey", async () => {
  await generateKey(rsaKey("Encrypting"));
  await generateKey(rsaKey("Signing"));
  await generateKey(aesKey("Wrapping"));
  await generateKey(aesKey("Fixed length encryption"));
  await generateKey(aesKey("Variable length encryption"));
  await generateKey(aesKey("Integrity protection"));
  await generateKey(hmacKey("SHA-256"));
  await generateKey(ecKey("Encrypting"));
  await generateKey(ecKey("Signing"));
  await generateKey(edKey());
  await generateKey(xKey());
});
