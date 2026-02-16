import { z } from "zod";

const appSchema = z.object({
  appVersion: z.string().min(1),
  unityVersion: z.string().min(1),
  buildFingerprint: z.string().min(1),
  manufacturer: z.string().min(1),
  model: z.string().min(1)
});

const attestationSchema = z.object({
  challengeB64: z.string().min(1),
  certChainB64: z.array(z.string()).min(0),
  errorCode: z.string().nullable().optional()
});

const idsSchema = z.object({
  widevineIdSha256: z.string().regex(/^[a-f0-9]{64}$/).or(z.literal("")),
  sensorFingerprintSha256: z.string().regex(/^[a-f0-9]{64}$/).or(z.literal(""))
});

const auditSchema = z.object({
  rootScore: z.number().int().min(0).max(25),
  hookScore: z.number().int().min(0).max(25),
  virtScore: z.number().int().min(0).max(25),
  tamperScore: z.number().int().min(0).max(25),
  findings: z.array(z.string()),
  errorCode: z.string().nullable().optional()
});

const clientScoreSchema = z.object({
  localRiskScore: z.number().int().min(0).max(100),
  suggestedAction: z.enum(["ALLOW", "FRICTION", "RESTRICT", "BLOCK"])
});

const metaSchema = z.object({
  totalMs: z.number().int().min(0),
  keystoreMs: z.number().int().min(0).optional(),
  widevineMs: z.number().int().min(0).optional(),
  sensorMs: z.number().int().min(0).optional(),
  auditMs: z.number().int().min(0).optional(),
  errorCodes: z.array(z.string()).optional(),
  nonceB64: z.string().min(1),
  collectedAtEpochMs: z.number().int().min(0)
});

export const verifyRequestSchema = z.object({
  app: appSchema,
  attestation: attestationSchema,
  ids: idsSchema,
  audit: auditSchema,
  clientScore: clientScoreSchema,
  meta: metaSchema
});

export type VerifyRequest = z.infer<typeof verifyRequestSchema>;

export type VerifyResponse = {
  verdict: "ALLOW" | "FRICTION" | "RESTRICT" | "BLOCK";
  riskScore: number;
  reasonCodes: string[];
  ttlSeconds: number;
};
