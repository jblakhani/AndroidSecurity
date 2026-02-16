import { X509Certificate, createPublicKey } from "crypto";

export type AttestationCheck = {
  ok: boolean;
  reasonCodes: string[];
};

const GOOGLE_ROOT_ISSUER_MARKERS = [
  "Google",
  "Android",
  "Android Keystore"
];

export function verifyAttestationChain(challengeB64: string, certChainB64: string[]): AttestationCheck {
  const reasonCodes: string[] = [];

  if (!challengeB64 || certChainB64.length === 0) {
    return { ok: false, reasonCodes: ["ATTESTATION_MISSING"] };
  }

  const challenge = decodeChallenge(challengeB64);
  if (!challenge) {
    return { ok: false, reasonCodes: ["ATTESTATION_CHALLENGE_INVALID"] };
  }

  if (challenge.length < 16 || challenge.length > 128) {
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
    const isValid = child.verify(createPublicKey(issuer.publicKey));
    if (!isValid) {
      return { ok: false, reasonCodes: ["ATTESTATION_CHAIN_SIGNATURE_INVALID"] };
    }
  }

  const root = certs[certs.length - 1];
  const rootIssuer = root.issuer;
  const rootLooksExpected = GOOGLE_ROOT_ISSUER_MARKERS.some((marker) => rootIssuer.includes(marker));
  if (!rootLooksExpected) {
    return { ok: false, reasonCodes: ["ATTESTATION_ROOT_UNTRUSTED"] };
  }

  const leafRaw = certs[0].raw;
  if (!leafRaw.includes(challenge)) {
    return { ok: false, reasonCodes: ["ATTESTATION_CHALLENGE_MISMATCH"] };
  }

  reasonCodes.push("ATTESTATION_CHAIN_OK", "ATTESTATION_CHALLENGE_OK");
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
