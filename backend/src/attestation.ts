import { X509Certificate, createPublicKey } from "crypto";

export type AttestationCheck = {
  ok: boolean;
  reasonCodes: string[];
};

export function verifyAttestationChain(challengeB64: string, certChainB64: string[]): AttestationCheck {
  const reasonCodes: string[] = [];

  if (!challengeB64 || certChainB64.length === 0) {
    return { ok: false, reasonCodes: ["ATTESTATION_MISSING"] };
  }

  let challenge: Buffer;
  try {
    challenge = Buffer.from(challengeB64, "base64");
  } catch {
    return { ok: false, reasonCodes: ["ATTESTATION_CHALLENGE_INVALID"] };
  }

  if (challenge.length < 16 || challenge.length > 128) {
    return { ok: false, reasonCodes: ["ATTESTATION_CHALLENGE_SIZE_INVALID"] };
  }

  let certs: X509Certificate[];
  try {
    certs = certChainB64.map((b64) => new X509Certificate(Buffer.from(b64, "base64")));
  } catch {
    return { ok: false, reasonCodes: ["ATTESTATION_CERT_PARSE_FAILED"] };
  }

  if (certs.length < 2) {
    return { ok: false, reasonCodes: ["ATTESTATION_CHAIN_TOO_SHORT"] };
  }

  for (let i = 0; i < certs.length - 1; i++) {
    const child = certs[i];
    const issuer = certs[i + 1];
    const isValid = child.verify(createPublicKey(issuer.publicKey));
    if (!isValid) {
      return { ok: false, reasonCodes: ["ATTESTATION_CHAIN_SIGNATURE_INVALID"] };
    }
  }

  const leafRaw = certs[0].raw;
  if (!leafRaw.includes(challenge)) {
    return { ok: false, reasonCodes: ["ATTESTATION_CHALLENGE_MISMATCH"] };
  }

  reasonCodes.push("ATTESTATION_CHAIN_OK", "ATTESTATION_CHALLENGE_OK");
  return { ok: true, reasonCodes };
}
