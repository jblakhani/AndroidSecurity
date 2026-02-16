import { X509Certificate, createHash, createPublicKey } from "crypto";
import { existsSync, readFileSync } from "fs";
import path from "path";

export type AttestationCheck = {
  ok: boolean;
  reasonCodes: string[];
};

const ANDROID_KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
const ATTESTATION_CHALLENGE_MIN = 16;
const ATTESTATION_CHALLENGE_MAX = 128;

const SECURITY_LEVEL_LABELS: Record<number, string> = {
  0: "SOFTWARE",
  1: "TRUSTED_ENVIRONMENT",
  2: "STRONG_BOX"
};

// Built-in Google Android attestation root certificate SHA-256 pins (DER cert hash).
// Operators can extend using file/env sources without code changes.
const DEFAULT_ROOT_CERT_SHA256_PINS = [
  "f92009e853b6b0454c7e1a7f6df83f6a7f2b6c9f4aee2b5f87c8f6f9e1ab7d4d"
] as const;

const DEFAULT_PIN_FILE_RELATIVE = "config/attestation_root_pins.txt";

export function verifyAttestationChain(challengeB64: string, certChainB64: string[]): AttestationCheck {
  if (!challengeB64 || certChainB64.length === 0) {
    return { ok: false, reasonCodes: ["ATTESTATION_MISSING"] };
  }

  const challenge = decodeChallenge(challengeB64);
  if (!challenge) {
    return { ok: false, reasonCodes: ["ATTESTATION_CHALLENGE_INVALID"] };
  }

  if (challenge.length < ATTESTATION_CHALLENGE_MIN || challenge.length > ATTESTATION_CHALLENGE_MAX) {
    return { ok: false, reasonCodes: ["ATTESTATION_CHALLENGE_SIZE_INVALID"] };
  }

  const certs = decodeCertificates(certChainB64);
  if (!certs) {
    return { ok: false, reasonCodes: ["ATTESTATION_CERT_PARSE_FAILED"] };
  }

  if (certs.length < 2) {
    return { ok: false, reasonCodes: ["ATTESTATION_CHAIN_TOO_SHORT"] };
  }

  const now = Date.now();
  for (const cert of certs) {
    const validFromMs = Date.parse(cert.validFrom);
    const validToMs = Date.parse(cert.validTo);
    if (!Number.isFinite(validFromMs) || !Number.isFinite(validToMs) || now < validFromMs || now > validToMs) {
      return { ok: false, reasonCodes: ["ATTESTATION_CERT_TIME_INVALID"] };
    }
  }

  for (let i = 0; i < certs.length - 1; i++) {
    const child = certs[i];
    const issuer = certs[i + 1];
    if (!child.verify(createPublicKey(issuer.publicKey))) {
      return { ok: false, reasonCodes: ["ATTESTATION_CHAIN_SIGNATURE_INVALID"] };
    }
  }

  const root = certs[certs.length - 1];
  if (!root.verify(createPublicKey(root.publicKey))) {
    return { ok: false, reasonCodes: ["ATTESTATION_ROOT_NOT_SELF_SIGNED"] };
  }

  const allowedPins = getAllowedRootPins();
  if (allowedPins.size === 0) {
    return { ok: false, reasonCodes: ["ATTESTATION_ROOT_PINSET_EMPTY"] };
  }

  const rootFingerprint = sha256Hex(root.raw);
  if (!allowedPins.has(rootFingerprint)) {
    return { ok: false, reasonCodes: ["ATTESTATION_ROOT_UNTRUSTED"] };
  }

  const leaf = certs[0];
  if (leaf.publicKey.asymmetricKeyType !== "ec") {
    return { ok: false, reasonCodes: ["ATTESTATION_KEY_TYPE_INVALID"] };
  }

  const parsed = parseAndroidAttestationExtension(leaf.raw);
  if (!parsed.ok) {
    return { ok: false, reasonCodes: [parsed.reasonCode] };
  }

  if (!timingSafeEqual(parsed.attestationChallenge, challenge)) {
    return { ok: false, reasonCodes: ["ATTESTATION_CHALLENGE_MISMATCH"] };
  }

  const reasonCodes = [
    "ATTESTATION_CHAIN_OK",
    "ATTESTATION_ROOT_PIN_OK",
    "ATTESTATION_EXTENSION_PARSED",
    "ATTESTATION_CHALLENGE_OK",
    `ATTESTATION_SECURITY_LEVEL_${SECURITY_LEVEL_LABELS[parsed.attestationSecurityLevel] ?? "UNKNOWN"}`,
    `KEYMASTER_SECURITY_LEVEL_${SECURITY_LEVEL_LABELS[parsed.keymasterSecurityLevel] ?? "UNKNOWN"}`
  ];

  return { ok: true, reasonCodes };
}

function decodeChallenge(challengeB64: string): Buffer | null {
  try {
    return Buffer.from(challengeB64, "base64");
  } catch {
    return null;
  }
}

function decodeCertificates(certChainB64: string[]): X509Certificate[] | null {
  try {
    return certChainB64.map((b64) => new X509Certificate(Buffer.from(b64, "base64")));
  } catch {
    return null;
  }
}

function getAllowedRootPins(): Set<string> {
  const pinFilePath = process.env.ATTESTATION_ROOT_PIN_FILE || path.join(process.cwd(), DEFAULT_PIN_FILE_RELATIVE);
  const filePins = loadPinsFromFile(pinFilePath);
  const envPins = (process.env.ATTESTATION_ROOT_SHA256_PINS ?? "")
    .split(",")
    .map((v) => v.trim().toLowerCase())
    .filter((v) => /^[a-f0-9]{64}$/.test(v));

  return new Set([...DEFAULT_ROOT_CERT_SHA256_PINS, ...filePins, ...envPins]);
}

function loadPinsFromFile(filePath: string): string[] {
  try {
    if (!existsSync(filePath)) {
      return [];
    }

    return readFileSync(filePath, "utf8")
      .split(/\r?\n/)
      .map((line) => line.trim().toLowerCase())
      .filter((line) => line.length > 0 && !line.startsWith("#"))
      .filter((line) => /^[a-f0-9]{64}$/.test(line));
  } catch {
    return [];
  }
}

function sha256Hex(input: Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

function timingSafeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

type ParsedAttestationExtension =
  | {
      ok: true;
      attestationSecurityLevel: number;
      keymasterSecurityLevel: number;
      attestationChallenge: Buffer;
    }
  | {
      ok: false;
      reasonCode: string;
    };

function parseAndroidAttestationExtension(certDer: Buffer): ParsedAttestationExtension {
  const certificate = readElement(certDer, 0);
  if (!certificate || certificate.end !== certDer.length || certificate.tag !== 0x30) {
    return { ok: false, reasonCode: "ATTESTATION_CERT_DER_INVALID" };
  }

  const rootChildren = readChildren(certificate.value);
  if (!rootChildren || rootChildren.length < 1 || rootChildren[0].tag !== 0x30) {
    return { ok: false, reasonCode: "ATTESTATION_CERT_TBS_MISSING" };
  }

  const tbsChildren = readChildren(rootChildren[0].value);
  if (!tbsChildren) {
    return { ok: false, reasonCode: "ATTESTATION_CERT_TBS_PARSE_FAILED" };
  }

  for (const child of tbsChildren) {
    // [3] EXPLICIT Extensions
    if (child.tag === 0xa3) {
      const explicitChildren = readChildren(child.value);
      if (!explicitChildren || explicitChildren.length !== 1 || explicitChildren[0].tag !== 0x30) {
        return { ok: false, reasonCode: "ATTESTATION_EXTENSIONS_PARSE_FAILED" };
      }

      const extensions = readChildren(explicitChildren[0].value);
      if (!extensions) {
        return { ok: false, reasonCode: "ATTESTATION_EXTENSIONS_PARSE_FAILED" };
      }

      for (const ext of extensions) {
        if (ext.tag !== 0x30) continue;
        const extFields = readChildren(ext.value);
        if (!extFields || extFields.length < 2) continue;

        const oidField = extFields[0];
        if (oidField.tag !== 0x06) continue;

        const oid = decodeOid(oidField.value);
        if (oid !== ANDROID_KEY_ATTESTATION_OID) continue;

        const octet = extFields[extFields.length - 1];
        if (octet.tag !== 0x04) {
          return { ok: false, reasonCode: "ATTESTATION_EXTENSION_VALUE_INVALID" };
        }

        return parseKeyDescription(octet.value);
      }

      return { ok: false, reasonCode: "ATTESTATION_EXTENSION_MISSING" };
    }
  }

  return { ok: false, reasonCode: "ATTESTATION_EXTENSION_MISSING" };
}

function parseKeyDescription(der: Buffer): ParsedAttestationExtension {
  const root = readElement(der, 0);
  if (!root || root.end !== der.length || root.tag !== 0x30) {
    return { ok: false, reasonCode: "ATTESTATION_EXTENSION_VALUE_INVALID" };
  }

  const fields = readChildren(root.value);
  if (!fields || fields.length < 5) {
    return { ok: false, reasonCode: "ATTESTATION_KEY_DESCRIPTION_INVALID" };
  }

  const attestationSecurityLevel = readInteger(fields[1]);
  const keymasterSecurityLevel = readInteger(fields[3]);
  const challengeField = fields[4];

  if (attestationSecurityLevel == null || keymasterSecurityLevel == null || challengeField.tag !== 0x04) {
    return { ok: false, reasonCode: "ATTESTATION_KEY_DESCRIPTION_INVALID" };
  }

  return {
    ok: true,
    attestationSecurityLevel,
    keymasterSecurityLevel,
    attestationChallenge: challengeField.value
  };
}

type DerElement = {
  tag: number;
  length: number;
  headerLength: number;
  start: number;
  end: number;
  value: Buffer;
};

function readElement(input: Buffer, offset: number): DerElement | null {
  if (offset + 2 > input.length) return null;

  const tag = input[offset];
  let idx = offset + 1;
  const firstLen = input[idx++];

  let length = 0;
  if ((firstLen & 0x80) === 0) {
    length = firstLen;
  } else {
    const bytes = firstLen & 0x7f;
    if (bytes === 0 || bytes > 4 || idx + bytes > input.length) return null;
    for (let i = 0; i < bytes; i++) {
      length = (length << 8) | input[idx++];
    }
  }

  const end = idx + length;
  if (end > input.length) return null;

  return {
    tag,
    length,
    headerLength: idx - offset,
    start: offset,
    end,
    value: input.subarray(idx, end)
  };
}

function readChildren(sequenceValue: Buffer): DerElement[] | null {
  const out: DerElement[] = [];
  let cursor = 0;

  while (cursor < sequenceValue.length) {
    const child = readElement(sequenceValue, cursor);
    if (!child) return null;
    out.push(child);
    cursor = child.end;
  }

  return out;
}

function decodeOid(encoded: Buffer): string {
  if (encoded.length === 0) return "";

  const first = encoded[0];
  const parts = [Math.floor(first / 40), first % 40];

  let value = 0;
  for (let i = 1; i < encoded.length; i++) {
    const byte = encoded[i];
    value = (value << 7) | (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }

  if (value !== 0) {
    return "";
  }

  return parts.join(".");
}

function readInteger(el: DerElement | undefined): number | null {
  if (!el || el.tag !== 0x02 || el.value.length === 0 || el.value.length > 4) {
    return null;
  }

  let value = 0;
  for (const b of el.value) {
    value = (value << 8) | b;
  }
  return value;
}
