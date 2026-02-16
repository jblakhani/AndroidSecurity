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

## Step-by-step guide for Unity 3D engineer

1. **Import plugin files into Unity project**
   - Copy `Assets/Plugins/Security` and `Assets/Plugins/Android/Security` into your Unity project.
   - In Unity Editor, verify Kotlin/Android plugin files are visible under `Assets/Plugins/Android/Security`.

2. **Configure Unity Android player settings**
   - Set **Build Settings → Platform = Android**.
   - Set **Player Settings → Other Settings → Scripting Backend = IL2CPP**.
   - Set **Target Architectures** to include at least `ARM64`.
   - Set **Minimum API Level** to `Android 6.0 (API 23)` or higher.

3. **Enable custom Gradle build (if your project requires it)**
   - In **Player Settings → Publishing Settings**, enable:
     - `Custom Main Gradle Template`
     - `Custom Base Gradle Template` (if needed by your pipeline)
   - Ensure your Unity-generated Gradle project includes this library module at build time.

4. **Validate manifest and permissions policy**
   - Confirm no dangerous permissions are added for this SDK.
   - This SDK does not require `READ_PHONE_STATE` or other privileged identifiers.

5. **Create game bootstrap script**
   - Add a C# MonoBehaviour (for example `DeviceRiskBootstrap.cs`) and initialize SDK once (login/session start or matchmaking entry).

6. **Collect risk profile with timeout-safe options**
   - Example:
   ```csharp
   using Company.Security;
   using Company.Security.Models;
   using UnityEngine;

   public class DeviceRiskBootstrap : MonoBehaviour
   {
       private readonly DeviceIdentitySDK _sdk = new DeviceIdentitySDK();

       private async void Start()
       {
           var opts = new CollectOptions
           {
               sampleCount = 200,
               sensorDurationMs = 1500,
               enableWidevine = true,
               enableAudit = true,
               timeoutMs = 4000
           };

           ChallengeResponse challenge = await _sdk.GetChallengeAsync(new Uri("https://api.example.com/device/challenge"));
           opts.nonceB64 = challenge.nonceB64;
           DeviceRiskProfile profile = await _sdk.CollectAsync(opts);
           ServerVerdict verdict = await _sdk.VerifyWithServerAsync(profile, new Uri("https://api.example.com/device/verify"));
           Debug.Log($"ServerVerdict={verdict.verdict}, Score={verdict.riskScore}");
       }
   }
   ```

7. **Call challenge endpoint before collection**
   - Get nonce first using `GetChallengeAsync(challengeEndpoint)`.
   - Put returned nonce into `CollectOptions.nonceB64` before calling `CollectAsync`.

8. **Call server verification endpoint**
   - Use `VerifyWithServerAsync(profile, verifyEndpoint)` after collection.
   - Recommended flow:
     - `GET /device/challenge`
     - set `opts.nonceB64 = challenge.nonceB64`
     - `CollectAsync(opts)`
     - `POST /device/verify`
     - Cache `verdict` until TTL expiry

9. **Use suggested action for game gating**
   - `ALLOW`: normal flow
   - `FRICTION`: add soft friction (extra validation/challenge)
   - `RESTRICT`: reduce trust-sensitive actions
   - `BLOCK`: deny high-risk entry

10. **Run SelfTest in QA build**
   - Call `SelfTestAsync()` to verify signal availability and timing without exposing raw identifiers.
   - Use this during device matrix testing before production rollout.

11. **Production rollout checklist**
    - Test on Android 10–14 physical devices.
    - Validate StrongBox fallback behavior on devices without StrongBox.
    - Confirm timeout behavior under CPU pressure.
    - Confirm no raw Widevine ID is logged/stored by analytics/crash tooling.

## Step-by-step guide for backend engineer (TypeScript)

1. **Open backend project**
   - Backend code is in `backend/`.
   - Endpoints implemented:
     - `GET /device/challenge`
     - `POST /device/verify`

2. **Install and build**
   - `cd backend`
   - `npm install`
   - `npm run build`

3. **Run locally**
   - Export root certificate pins first (required):
     - `export ATTESTATION_ROOT_SHA256_PINS="<root_sha256_hex_1>,<root_sha256_hex_2>"`
   - `npm start`
   - Server binds to `PORT` env variable or `8080` by default.

4. **Challenge endpoint flow**
   - Client requests `GET /device/challenge`.
   - Backend issues a nonce (`nonceB64`) with expiry (`expiresAt`).
   - Nonce is single-use and removed when consumed by `/device/verify`.

5. **Verify endpoint payload contract**
   - Validate request using strict schema (`zod`) in `backend/src/types.ts`.
   - Require these top-level sections:
     - `app`
     - `attestation`
     - `ids`
     - `audit`
     - `clientScore`
     - `meta`
   - `meta` must include `nonceB64` and `collectedAtEpochMs`.
   - `attestation.challengeB64` must exactly equal `meta.nonceB64` (strict challenge binding).
   - `collectedAtEpochMs` must be fresh (within server acceptance window).

6. **Attestation verification path**
   - Parse X.509 cert chain from base64 DER.
   - Verify chain signatures leaf-to-root and ensure root is self-signed.
   - Enforce pinned root trust: set `ATTESTATION_ROOT_SHA256_PINS` (comma-separated SHA-256 hex of full DER root certs).
   - Parse Android key attestation extension OID `1.3.6.1.4.1.11129.2.1.17` from leaf cert DER.
   - Decode `attestationSecurityLevel`, `keymasterSecurityLevel`, and `attestationChallenge` from KeyDescription.
   - Enforce `meta.nonceB64 == attestation.challengeB64` and extension `attestationChallenge` equality.
   - Add reason codes (`ATTESTATION_CHAIN_OK`, `ATTESTATION_ROOT_PIN_OK`, `ATTESTATION_CHALLENGE_OK`, or deterministic failure codes).

7. **Risk graph update**
   - Key graph by `widevineIdSha256` (hashed identifier only).
   - Keep rolling risk, seen count, first/last seen timestamps.
   - Maintain sensor-to-widevine map to detect anomaly: widevine changed while sensor remains stable.
   - Client SDK also persists sensor->widevine hash mapping locally and applies `+20` local score on stable-sensor ID change.

8. **Server-side scoring and verdict**
   - Apply scoring rules and cap to `0..100`.
   - Merge server score with client score using max.
   - Return deterministic response:
     - `verdict`
     - `riskScore`
     - `reasonCodes`
     - `ttlSeconds`

9. **Production hardening checklist**
   - Replace in-memory stores with Redis/PostgreSQL.
   - Add rate limiting and auth on both endpoints.
   - Add structured logging with no raw identifiers.
   - Add monitoring on nonce failures, attestation failures, and verdict distributions.

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
    "errorCodes": [],
    "nonceB64": "N7fQ6cUK4QJf1D9uXfW5P2Zp6k8m3Y8U8hCq6mV6Y0Y=",
    "collectedAtEpochMs": 1719791012000
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
