import { randomBytes } from "crypto";

export function randomNonceB64(bytes = 32): string {
  return randomBytes(bytes).toString("base64");
}

export function nowEpochMs(): number {
  return Date.now();
}
