import type { VerifyRequest } from "./types.js";

export type RiskResult = {
  score: number;
  reasonCodes: string[];
  verdict: "ALLOW" | "FRICTION" | "RESTRICT" | "BLOCK";
};

export function computeRisk(req: VerifyRequest, attestationOk: boolean, widevineChangedSensorStable: boolean): RiskResult {
  let score = 0;
  const reasonCodes: string[] = [];

  if (!attestationOk) {
    score += 50;
    reasonCodes.push("ATTESTATION_FAILED");
  }

  if (!req.ids.widevineIdSha256) {
    score += 25;
    reasonCodes.push("WIDEVINE_UNAVAILABLE");
  }

  if (!req.ids.sensorFingerprintSha256) {
    score += 15;
    reasonCodes.push("SENSOR_FINGERPRINT_UNAVAILABLE");
  }

  if (req.audit.hookScore >= 18) {
    score += 40;
    reasonCodes.push("HOOK_STRONG");
  }

  if (req.audit.rootScore >= 15) {
    score += 30;
    reasonCodes.push("ROOT_STRONG");
  }

  if (req.audit.virtScore >= 15) {
    score += 25;
    reasonCodes.push("VIRTUALIZATION_STRONG");
  }

  if (widevineChangedSensorStable) {
    score += 20;
    reasonCodes.push("ID_CHANGED_SENSOR_STABLE_ANOMALY");
  }

  if (req.meta.totalMs > 4000) {
    score += 10;
    reasonCodes.push("CLIENT_COLLECTION_OVERTIME");
  }

  score = Math.min(100, score);

  const highSignals = [req.audit.rootScore, req.audit.hookScore, req.audit.virtScore].filter((s) => s >= 18).length;
  const extremeEvidence = req.audit.hookScore >= 22 || req.audit.rootScore >= 22;

  let verdict: RiskResult["verdict"] = "ALLOW";
  if (score >= 80) {
    verdict = highSignals >= 2 || extremeEvidence ? "BLOCK" : "RESTRICT";
  } else if (score >= 60) {
    verdict = "RESTRICT";
  } else if (score >= 30) {
    verdict = "FRICTION";
  }

  if (reasonCodes.length === 0) {
    reasonCodes.push("SIGNALS_STABLE");
  }

  return { score, reasonCodes, verdict };
}
