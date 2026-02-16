export type NonceEntry = {
  nonceB64: string;
  expiresAtEpochMs: number;
  issuedAtEpochMs: number;
};

export type IdentifierNode = {
  idHash: string;
  firstSeenEpochMs: number;
  lastSeenEpochMs: number;
  seenCount: number;
  rollingRisk: number;
  lastSensorHash: string;
};

export class InMemoryStore {
  private nonces = new Map<string, NonceEntry>();
  private graph = new Map<string, IdentifierNode>();

  putNonce(entry: NonceEntry): void {
    this.nonces.set(entry.nonceB64, entry);
  }

  consumeValidNonce(nonceB64: string, nowEpochMs: number): boolean {
    const entry = this.nonces.get(nonceB64);
    if (!entry) return false;
    this.nonces.delete(nonceB64);
    return nowEpochMs <= entry.expiresAtEpochMs;
  }

  upsertNode(idHash: string, sensorHash: string, riskScore: number, nowEpochMs: number): IdentifierNode {
    const prev = this.graph.get(idHash);
    if (!prev) {
      const created: IdentifierNode = {
        idHash,
        firstSeenEpochMs: nowEpochMs,
        lastSeenEpochMs: nowEpochMs,
        seenCount: 1,
        rollingRisk: riskScore,
        lastSensorHash: sensorHash
      };
      this.graph.set(idHash, created);
      return created;
    }

    const next: IdentifierNode = {
      ...prev,
      lastSeenEpochMs: nowEpochMs,
      seenCount: prev.seenCount + 1,
      rollingRisk: Math.round(prev.rollingRisk * 0.7 + riskScore * 0.3),
      lastSensorHash: sensorHash || prev.lastSensorHash
    };
    this.graph.set(idHash, next);
    return next;
  }
}
