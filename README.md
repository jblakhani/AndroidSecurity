# Durable Device Identity & Risk Profiling SDK (Unity + Android)

## Folder Structure

- `Assets/Plugins/Security/DeviceIdentitySDK.cs`
- `Assets/Plugins/Security/Models/DeviceIdentityModels.cs`
- `Assets/Plugins/Android/Security/build.gradle`
- `Assets/Plugins/Android/Security/proguard-rules.pro`
- `Assets/Plugins/Android/Security/src/main/AndroidManifest.xml`
- `Assets/Plugins/Android/Security/src/main/java/com/company/security/DeviceIdentityBridge.kt`
- `Assets/Plugins/Android/Security/src/main/java/com/company/security/KeystoreAttestation.kt`
- `Assets/Plugins/Android/Security/src/main/java/com/company/security/WidevineId.kt`
- `Assets/Plugins/Android/Security/src/main/java/com/company/security/SensorFingerprint.kt`
- `Assets/Plugins/Android/Security/src/main/java/com/company/security/EnvironmentAudit.kt`

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
   - SDK caches verdicts in-memory until `ttlSeconds` expiry (cache key uses endpoint + app version + hashed Widevine + hashed sensor fingerprint).
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
   - Built-in Google attestation root pins are included by default.
   - You can maintain pins offline in `backend/config/attestation_root_pins.txt` (one SHA-256 pin per line).
   - Optional env-based extension/override for emergency rotation:
     - `export ATTESTATION_ROOT_SHA256_PINS="<extra_root_sha256_hex_1>,<extra_root_sha256_hex_2>"`
     - `export ATTESTATION_ROOT_PIN_FILE="/absolute/path/to/attestation_root_pins.txt"`
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
   - Enforce pinned root trust from layered sources:
     - built-in defaults in backend,
     - optional `backend/config/attestation_root_pins.txt`,
     - optional `ATTESTATION_ROOT_SHA256_PINS` and `ATTESTATION_ROOT_PIN_FILE` overrides.
   - Monitor `ATTESTATION_ROOT_UNTRUSTED`/`ATTESTATION_ROOT_PINSET_EMPTY` errors and update pins before root rotations impact traffic.
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
  "reasonCodes": ["ATTESTATION_CHAIN_OK", "ATTESTATION_CHALLENGE_OK", "SIGNALS_STABLE"],
  "ttlSeconds": 21600
}
```

## Debugging and observability

- Unity layer logs with tag `[DeviceIdentitySDK]` for challenge, collect, verify, cache hits/misses, and self-test lifecycle.
- Android layer logs with tags:
  - `DeviceIdentityBridge`
  - `KeystoreAttestation`
  - `WidevineId`
  - `SensorFingerprint`
  - `EnvironmentAudit`
- Backend logs with prefix `[device-backend]` at `INFO/WARN` for challenge issuance, verify rejects, anomaly detection, and final verdict summary.
- Logs intentionally avoid raw identifiers; only hashed identifiers and high-level state are emitted.

## Performance and compatibility notes

- Entire collection runs in a single background executor with bounded timeout (default 4000 ms).
- Keystore attestation uses EC P-256 with challenge, StrongBox preferred on API 28+ and fallback supported.
- Widevine `PROPERTY_DEVICE_UNIQUE_ID` is SHA-256 hashed immediately and never persisted in raw form.
- Sensor collection requires accelerometer and uses gyroscope when available, without dangerous permissions.
- `/proc/self/maps` checks are read-only and best-effort; failures return `PROC_READ_DENIED` without crashing.
- Risk scoring clamps to `[0,100]` and action mapping avoids `BLOCK` on a single medium-confidence signal.
- Compatible target: Android 10–14+ with minSdk 23.

## Ultra-detailed setup checklist (for first-time integrators)

If you want a no-assumption setup, follow this exact sequence and do not skip steps.

### A) Unity + Android plugin setup (click-by-click)

1. **Create/prepare project**
   - Unity version: `2021.x` or newer.
   - Platform target must be Android.
   - Scripting backend must be IL2CPP.

2. **Copy folders to exact paths**
   - Copy `Assets/Plugins/Security` into your Unity project.
   - Copy `Assets/Plugins/Android/Security` into your Unity project.
   - Final paths must match exactly:
     - `Assets/Plugins/Security/DeviceIdentitySDK.cs`
     - `Assets/Plugins/Security/Models/DeviceIdentityModels.cs`
     - `Assets/Plugins/Android/Security/src/main/java/com/company/security/...`

3. **Reimport and verify Unity sees files**
   - In Unity Project window, confirm all C# files are visible.
   - Confirm Android/Kotlin files exist in the same package paths.
   - If files are missing in Project view, right-click `Assets` → `Reimport`.

4. **Player settings sanity**
   - `Build Settings -> Android -> Switch Platform`.
   - `Player Settings -> Other Settings`:
     - `Minimum API Level`: 23+
     - `Target Architectures`: include ARM64
     - `Scripting Backend`: IL2CPP

5. **Create one bootstrap script and run only once per session**
   - Place bootstrap on login scene or matchmaking pre-check scene.
   - Do not call `CollectAsync` repeatedly every frame.

6. **Use the required call order (mandatory)**
   - `GetChallengeAsync(...)`
   - set `CollectOptions.nonceB64`
   - `CollectAsync(...)`
   - `VerifyWithServerAsync(...)`
   - use `ServerVerdict` + `suggestedAction` for gating

7. **Minimum production-safe `CollectOptions`**
   - `sampleCount = 200`
   - `sensorDurationMs = 1500`
   - `enableWidevine = true`
   - `enableAudit = true`
   - `timeoutMs = 4000`

8. **Expected successful behavior**
   - `profile.localRiskScore` between `0..100`
   - `profile.suggestedAction` one of `ALLOW/FRICTION/RESTRICT/BLOCK`
   - `collectionMeta.errorCodes` should usually be empty on clean devices

9. **Expected fallback behavior (non-Android or editor)**
   - SDK returns fallback profile with `PLATFORM_UNSUPPORTED`.
   - This is expected in editor tests.

10. **Run SelfTest before shipping**
    - Call `SelfTestAsync()` from QA menu.
    - Verify booleans for keystore/widevine/accelerometer/proc readability.
    - Track `timingsMs` to detect slow devices.

11. **Do not treat one signal as absolute truth**
    - Keep backend verify mandatory for final trust decisions.
    - Use local action as pre-gate; server verdict as authoritative gate.

### B) Backend setup (step-by-step with expected outputs)

1. **Install dependencies and build**
   - `cd backend`
   - `npm install`
   - `npm run build`

2. **Prepare root pin configuration**
   - Default pin file: `backend/config/attestation_root_pins.txt`.
   - Add one pin per line (SHA-256 of DER root cert).
   - Optional overrides:
     - `ATTESTATION_ROOT_SHA256_PINS` (comma-separated)
     - `ATTESTATION_ROOT_PIN_FILE` (absolute path)

3. **Run service**
   - `npm start`
   - Expect startup log similar to:
     - `[device-backend][INFO] Device identity backend listening on :8080`

4. **Verify challenge endpoint first**
   - Call `GET /device/challenge`.
   - Expect JSON with `nonceB64` and `expiresAt`.

5. **Verify endpoint contract (strict)**
   - `POST /device/verify` must include:
     - `app`, `attestation`, `ids`, `audit`, `clientScore`, `meta`
   - Mandatory strict checks:
     - `meta.nonceB64` present
     - `meta.collectedAtEpochMs` present
     - `meta.nonceB64 == attestation.challengeB64`

6. **Expected reject responses**
   - Invalid body: `PAYLOAD_INVALID`
   - Expired/unknown nonce: `NONCE_INVALID_OR_EXPIRED`
   - Nonce/challenge mismatch: `NONCE_ATTESTATION_MISMATCH`
   - Old/skewed timestamp: `COLLECTION_TIMESTAMP_INVALID`

7. **Expected success response**
   - `verdict` in `ALLOW/FRICTION/RESTRICT/BLOCK`
   - `riskScore` in `0..100`
   - `reasonCodes` non-empty
   - `ttlSeconds` present

8. **Rollout safety checklist**
   - Keep logs on for staging (`[device-backend]`, `[DeviceIdentitySDK]`, Android tags).
   - Validate behavior on rooted, emulator, and clean physical devices.
   - Validate timeout behavior under CPU stress.
   - Confirm no pipeline logs store raw identifiers.

### C) Quick troubleshooting map (symptom -> check)

- **Symptom:** Always getting `PAYLOAD_INVALID`
  - Check request JSON contains all top-level sections and `meta.nonceB64`.

- **Symptom:** `NONCE_INVALID_OR_EXPIRED`
  - Ensure challenge request happens immediately before collection/verify.
  - Ensure nonce is not reused.

- **Symptom:** `NONCE_ATTESTATION_MISMATCH`
  - Ensure `opts.nonceB64` equals challenge nonce exactly.
  - Ensure app is not overwriting options before collect call.

- **Symptom:** High local score on clean test devices
  - Inspect `collectionMeta.errorCodes` and audit findings.
  - Run `SelfTestAsync()` to identify missing signals.

- **Symptom:** Backend always returns restrictive verdicts
  - Check attestation root pin configuration and reason codes.
  - Verify server clock and client timestamp freshness window.

- **Symptom:** No sensor fingerprint
  - Accelerometer is required; gyro is optional.
  - Confirm device has accelerometer and sensor sampling duration is not too low.
