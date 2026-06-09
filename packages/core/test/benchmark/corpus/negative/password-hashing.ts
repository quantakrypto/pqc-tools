// Negative bait: password hashing with bcrypt / scrypt / argon2. These are
// symmetric KDFs, NOT quantum-vulnerable asymmetric crypto. Expected: no findings.
import bcrypt from "bcrypt";
import argon2 from "argon2";
import crypto from "node:crypto";

export async function hashWithBcrypt(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function hashWithArgon(password: string): Promise<string> {
  return argon2.hash(password);
}

export function hashWithScrypt(password: string, salt: Buffer): Buffer {
  return crypto.scryptSync(password, salt, 64);
}
