import express, { type Request, type Response } from "express";
import { createHash } from "crypto";
import { verifyRequestSchema, type VerifyResponse } from "./types.js";
import { randomNonceB64, nowEpochMs } from "./crypto.js";
import { InMemoryStore } from "./store.js";
import { verifyAttestationChain } from "./attestation.js";
import { computeRisk } from "./risk.js";

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "256kb" }));

const store = new InMemoryStore();
const sensorToWidevine = new Map<string, string>();

const CHALLENGE_TTL_SECONDS = 120;
const VERDICT_TTL_SECONDS = 6 * 60 * 60;
const COLLECTION_MAX_AGE_MS = 2 * 60 * 1000;

app.get("/device/challenge", (_req: Request, res: Response) => {
  const issuedAt = nowEpochMs();
  const expiresAt = issuedAt + CHALLENGE_TTL_SECONDS * 1000;
  const nonceB64 = randomNonceB64();

  store.putNonce({
    nonceB64,
    issuedAtEpochMs: issuedAt,
    expiresAtEpochMs: expiresAt
  });

  logInfo("challenge issued", { expiresAt });
  res.status(200).json({ nonceB64, expiresAt });
});

app.post("/device/verify", (req: Request, res: Response) => {
  const parsed = verifyRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    logWarn("verify payload invalid", { issueCount: parsed.error.issues.length });
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
    logWarn("verify rejected: invalid/expired nonce", { collectedAt: payload.meta.collectedAtEpochMs });
    res.status(400).json({
      verdict: "BLOCK",
      riskScore: 95,
      reasonCodes: ["NONCE_INVALID_OR_EXPIRED"],
      ttlSeconds: 30
    });
    return;
  }

  if (payload.meta.nonceB64 !== payload.attestation.challengeB64) {
    logWarn("verify rejected: nonce/challenge mismatch", { collectedAt: payload.meta.collectedAtEpochMs });
    res.status(400).json({
      verdict: "BLOCK",
      riskScore: 95,
      reasonCodes: ["NONCE_ATTESTATION_MISMATCH"],
      ttlSeconds: 30
    });
    return;
  }

  if (Math.abs(now - payload.meta.collectedAtEpochMs) > COLLECTION_MAX_AGE_MS) {
    logWarn("verify rejected: collection timestamp outside freshness window", {
      collectedAt: payload.meta.collectedAtEpochMs,
      now
    });
    res.status(400).json({
      verdict: "RESTRICT",
      riskScore: 70,
      reasonCodes: ["COLLECTION_TIMESTAMP_INVALID"],
      ttlSeconds: 60
    });
    return;
  }

  const clientIp = (
    req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() ??
    req.socket?.remoteAddress ??
    ""
  ).trim();
  const appFields = payload.app;
  const manufacturer = (appFields.manufacturer ?? "").trim();
  const model = (appFields.model ?? "").trim();
  const hardware = (appFields.hardware ?? "").trim();
  const device = (appFields.device ?? "").trim();
  const board = (appFields.board ?? "").trim();
  const product = (appFields.product ?? "").trim();
  const fingerprintInput = [manufacturer, model, hardware, device, board, product, clientIp].join("|");
  const deviceFingerprintWithIpSha256 = createHash("sha256").update(fingerprintInput, "utf8").digest("hex");

  const attestation = verifyAttestationChain(payload.attestation.challengeB64, payload.attestation.certChainB64);

  const sensorHash = payload.ids.sensorFingerprintSha256;
  const widevineHash = payload.ids.widevineIdSha256;

  let widevineChangedSensorStable = false;
  if (sensorHash && widevineHash) {
    const knownWidevine = sensorToWidevine.get(sensorHash);
    if (knownWidevine && knownWidevine !== widevineHash) {
      widevineChangedSensorStable = true;
      logWarn("stable-sensor identifier anomaly detected");
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
    ttlSeconds: VERDICT_TTL_SECONDS,
    deviceFingerprintWithIpSha256
  };

  //logInfo("verify completed", {
    //verdict: response.verdict,
    //riskScore: response.riskScore,
    //clientScore: payload.clientScore.localRiskScore,
    //attestationOk: attestation.ok,
    //reasonCount: response.reasonCodes.length,
    //widevineIdSha256: widevineHash || undefined,
    //sensorFingerprintSha256: sensorHash || undefined
  //});

  logInfo("device fingerprint, Device fingerprint with IP", {
    deviceFingerprintWithIpSha256,
    widevineIdSha256: widevineHash === "" ? "(empty)" : widevineHash,
    //sensorFingerprintSha256: sensorHash === "" ? "(empty)" : sensorHash
  });

  res.status(200).json(response);
});

const port = Number(process.env.PORT || 8080);
app.listen(port, () => {
  logInfo(`Device identity backend listening on :${port}`);
});

function logInfo(message: string, context?: Record<string, unknown>): void {
  process.stdout.write(`[device-backend][INFO] ${message}${context ? ` ${JSON.stringify(context)}` : ""}\n`);
}

function logWarn(message: string, context?: Record<string, unknown>): void {
  process.stdout.write(`[device-backend][WARN] ${message}${context ? ` ${JSON.stringify(context)}` : ""}\n`);
}
