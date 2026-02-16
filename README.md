# Durable Device Identity & Risk Profiling SDK (Unity + Android)

## Folder Structure

- `Assets/Plugins/Security/DeviceIdentitySDK.cs`
- `Assets/Plugins/Security/Models/DeviceIdentityModels.cs`
- `Assets/Plugins/Android/Security/build.gradle`
- `Assets/Plugins/Android/Security/proguard-rules.pro`
- `Assets/Plugins/Android/Security/CMakeLists.txt`
- `Assets/Plugins/Android/Security/src/main/AndroidManifest.xml`
- `Assets/Plugins/Android/Security/src/main/java/com/company/security/DeviceIdentityBridge.kt`
- `Assets/Plugins/Android/Security/src/main/java/com/company/security/KeystoreAttestation.kt`
- `Assets/Plugins/Android/Security/src/main/java/com/company/security/WidevineId.kt`
- `Assets/Plugins/Android/Security/src/main/java/com/company/security/SensorFingerprint.kt`
- `Assets/Plugins/Android/Security/src/main/java/com/company/security/EnvironmentAudit.kt`
- `Assets/Plugins/Android/Security/src/main/java/com/company/security/native-audit.cpp`

## Example request payload (`POST /device/verify`)

```json
{
  "app": {
    "appVersion": "1.9.0",
    "unityVersion": "2021.3.39f1",
    "buildFingerprint": "google/panther/panther:14/UQ1A.240205.002/1234567:user/release-keys",
    "manufacturer": "Google",
    "model": "Pixel 7"
  },
  "attestation": {
    "challengeB64": "l7f6f8zLh6h3S9I9P2x6JQXWnL2jV2L4fLQ5NQY7P2c=",
    "certChainB64": ["MIIC...", "MIID..."],
    "errorCode": null
  },
  "ids": {
    "widevineIdSha256": "2a7937d54e3374ec13b9ea06db9f6f4b4be4e78cf29f6e7757a70842f71f17de",
    "sensorFingerprintSha256": "950f5252ec7fbf4f5a2016c46c339e2dd456eb1de9f80357bd7f93289eac6f85"
  },
  "audit": {
    "rootScore": 0,
    "hookScore": 0,
    "virtScore": 0,
    "tamperScore": 0,
    "findings": [],
    "errorCode": null
  },
  "clientScore": {
    "localRiskScore": 0,
    "suggestedAction": "ALLOW"
  },
  "meta": {
    "totalMs": 913,
    "keystoreMs": 184,
    "widevineMs": 31,
    "sensorMs": 660,
    "auditMs": 38,
    "errorCodes": []
  }
}
```

## Example response payload

```json
{
  "verdict": "ALLOW",
  "riskScore": 12,
  "reasonCodes": ["ATTEST_OK", "SIGNALS_STABLE"],
  "ttlSeconds": 21600
}
```

## Performance and compatibility notes

- Entire collection runs in a single background executor with bounded timeout (default 4000 ms).
- Keystore attestation uses EC P-256 with challenge, StrongBox preferred on API 28+ and fallback supported.
- Widevine `PROPERTY_DEVICE_UNIQUE_ID` is SHA-256 hashed immediately and never persisted in raw form.
- Sensor collection reads accelerometer + gyroscope only, without dangerous permissions.
- `/proc/self/maps` checks are read-only and best-effort; failures return `PROC_READ_DENIED` without crashing.
- Risk scoring clamps to `[0,100]` and action mapping avoids `BLOCK` on a single medium-confidence signal.
- Compatible target: Android 10–14+ with minSdk 23.
