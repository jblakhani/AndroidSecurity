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

           DeviceRiskProfile profile = await _sdk.CollectAsync(opts);
           Debug.Log($"Risk={profile.localRiskScore}, Action={profile.suggestedAction}");
       }
   }
   ```

7. **Call server verification endpoint**
   - Use `VerifyWithServerAsync(profile, endpoint)` after collection.
   - Recommended flow:
     - Get nonce from `GET /device/challenge`
     - Collect profile
     - Send to `POST /device/verify`
     - Cache `verdict` until TTL expiry

8. **Use suggested action for game gating**
   - `ALLOW`: normal flow
   - `FRICTION`: add soft friction (extra validation/challenge)
   - `RESTRICT`: reduce trust-sensitive actions
   - `BLOCK`: deny high-risk entry

9. **Run SelfTest in QA build**
   - Call `SelfTestAsync()` to verify signal availability and timing without exposing raw identifiers.
   - Use this during device matrix testing before production rollout.

10. **Production rollout checklist**
    - Test on Android 10–14 physical devices.
    - Validate StrongBox fallback behavior on devices without StrongBox.
    - Confirm timeout behavior under CPU pressure.
    - Confirm no raw Widevine ID is logged/stored by analytics/crash tooling.

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
