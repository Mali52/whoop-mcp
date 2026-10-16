/**
 * At-rest encryption for WHOOP tokens stored in Supabase.
 *
 * AES-256-GCM with a key derived (HKDF-SHA256) from a server secret, so a
 * leaked database dump alone never exposes usable WHOOP credentials.
 * Ciphertext format: `v1.<iv>.<authTag>.<ciphertext>` (base64url parts).
 */

import { createCipheriv, createDecipheriv, hkdf, randomBytes } from "node:crypto";

const VERSION = "v1";
const HKDF_SALT = "whoop-mcp-token-encryption-v1";
const HKDF_INFO = "aes-256-gcm";
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

/** Derive a 32-byte AES key from an arbitrary-length server secret. */
export function deriveEncryptionKey(secret: string): Promise<Buffer> {
  if (!secret) {
    return Promise.reject(new Error("Token encryption secret must not be empty."));
  }
  return new Promise((resolve, reject) => {
    hkdf("sha256", secret, HKDF_SALT, HKDF_INFO, KEY_LENGTH, (err, key) => {
      if (err) reject(err);
      else resolve(Buffer.from(key));
    });
  });
}

/** Encrypt a UTF-8 string. Each call uses a fresh random IV. */
export function encryptString(plaintext: string, key: Buffer): string {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_LENGTH });
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [VERSION, iv, tag, ciphertext]
    .map((p) => (typeof p === "string" ? p : p.toString("base64url")))
    .join(".");
}

/**
 * Decrypt a value produced by {@link encryptString}.
 * Throws if the payload is malformed, tampered with, or encrypted with another key.
 */
export function decryptString(payload: string, key: Buffer): string {
  const parts = payload.split(".");
  if (parts.length !== 4 || parts[0] !== VERSION) {
    throw new Error("Unsupported encrypted token format.");
  }
  const [, iv, tag, ciphertext] = parts.map((p) => Buffer.from(p, "base64url")) as [
    Buffer,
    Buffer,
    Buffer,
    Buffer,
  ];
  // Node accepts truncated GCM tags unless the length is pinned.
  if (iv.length !== IV_LENGTH || tag.length !== TAG_LENGTH) {
    throw new Error("Unsupported encrypted token format.");
  }
  const decipher = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_LENGTH });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf-8");
}
