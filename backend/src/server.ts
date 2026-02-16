import express, { type Request, type Response } from "express";
import { verifyRequestSchema, type VerifyResponse } from "./types.js";
import { randomNonceB64, nowEpochMs } from "./crypto.js";
import { InMemoryStore } from "./store.js";
import { verifyAttestationChain } from "./attestation.js";
import { computeRisk } from "./risk.js";

const app = express();
app.use(express.json({ limit: "256kb" }));

const store = new InMemoryStore();
const sensorToWidevine = new Map<string, string>();

const CHALLENGE_TTL_SECONDS = 120;
const VERDICT_TTL_SECONDS = 6 * 60 * 60;

app.get("/device/challenge", (_req: Request, res: Response) => {
  const issuedAt = nowEpochMs();
  const expiresAt = issuedAt + CHALLENGE_TTL_SECONDS * 1000;
  const nonceB64 = randomNonceB64();

  store.putNonce({
    nonceB64,
    issuedAtEpochMs: issuedAt,
    expiresAtEpochMs: expiresAt
  });

  res.status(200).json({ nonceB64, expiresAt });
});

app.post("/device/verify", (req: Request, res: Response) => {
  const parsed = verifyRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      verdict: "RESTRICT",
      riskScore: 80,
      reasonCodes: ["PAYLOAD_INVALID"],
      ttlSeconds: 60
    });
    return;
  }

  const payload = parsed.data;
  const now = nowEpochMs();

  const nonceOk = store.consumeValidNonce(payload.meta.nonceB64, now);
  if (!nonceOk) {
    res.status(400).json({
      verdict: "BLOCK",
      riskScore: 95,
      reasonCodes: ["NONCE_INVALID_OR_EXPIRED"],
      ttlSeconds: 30
    });
    return;
  }

  const attestation = verifyAttestationChain(payload.attestation.challengeB64, payload.attestation.certChainB64);

  const sensorHash = payload.ids.sensorFingerprintSha256;
  const widevineHash = payload.ids.widevineIdSha256;

  let widevineChangedSensorStable = false;
  if (sensorHash && widevineHash) {
    const knownWidevine = sensorToWidevine.get(sensorHash);
    if (knownWidevine && knownWidevine !== widevineHash) {
      widevineChangedSensorStable = true;
    }
    sensorToWidevine.set(sensorHash, widevineHash);
  }

  const risk = computeRisk(payload, attestation.ok, widevineChangedSensorStable);
  const mergedReasons = [...risk.reasonCodes, ...attestation.reasonCodes];

  if (widevineHash) {
    store.upsertNode(widevineHash, sensorHash, risk.score, now);
  }

  const response: VerifyResponse = {
    verdict: risk.verdict,
    riskScore: Math.max(risk.score, payload.clientScore.localRiskScore),
    reasonCodes: Array.from(new Set(mergedReasons)).sort(),
    ttlSeconds: VERDICT_TTL_SECONDS
  };

  res.status(200).json(response);
});

const port = Number(process.env.PORT || 8080);
app.listen(port, () => {
  process.stdout.write(`Device identity backend listening on :${port}\n`);
});
