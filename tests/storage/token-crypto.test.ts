import { describe, it, expect } from "vitest";
import {
  decryptString,
  deriveEncryptionKey,
  encryptString,
} from "../../src/storage/token-crypto.js";

describe("token-crypto", () => {
  it("round-trips a value", async () => {
    const key = await deriveEncryptionKey("server-secret");
    const encrypted = encryptString("whoop-access-token", key);
    expect(encrypted.startsWith("v1.")).toBe(true);
    expect(encrypted).not.toContain("whoop-access-token");
    expect(decryptString(encrypted, key)).toBe("whoop-access-token");
  });

  it("uses a fresh IV per encryption", async () => {
    const key = await deriveEncryptionKey("server-secret");
    expect(encryptString("same", key)).not.toBe(encryptString("same", key));
  });

  it("derives the same key from the same secret", async () => {
    const a = await deriveEncryptionKey("secret");
    const b = await deriveEncryptionKey("secret");
    expect(a.equals(b)).toBe(true);
    expect(a).toHaveLength(32);
  });

  it("rejects decryption with a different key", async () => {
    const encrypted = encryptString("value", await deriveEncryptionKey("one"));
    const other = await deriveEncryptionKey("two");
    expect(() => decryptString(encrypted, other)).toThrow();
  });

  it("rejects tampered ciphertext", async () => {
    const key = await deriveEncryptionKey("secret");
    const parts = encryptString("value", key).split(".");
    parts[3] = Buffer.from("tampered").toString("base64url");
    expect(() => decryptString(parts.join("."), key)).toThrow();
  });

  it("rejects unknown formats", async () => {
    const key = await deriveEncryptionKey("secret");
    expect(() => decryptString("plain-text-token", key)).toThrow(
      "Unsupported encrypted token format."
    );
  });

  it("rejects an empty secret", async () => {
    await expect(deriveEncryptionKey("")).rejects.toThrow("must not be empty");
  });
});
