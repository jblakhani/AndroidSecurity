using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Company.Security.Models;
using UnityEngine;

namespace Company.Security
{
    public sealed class DeviceIdentitySDK
    {
        private const string BridgeClass = "com.company.security.DeviceIdentityBridge";
        private const string LogTag = "[DeviceIdentitySDK]";
        private static readonly ConcurrentDictionary<string, CachedVerdict> VerdictCache = new ConcurrentDictionary<string, CachedVerdict>();

        public async Task<ChallengeResponse> GetChallengeAsync(Uri challengeEndpoint)
        {
            if (challengeEndpoint == null) throw new ArgumentNullException(nameof(challengeEndpoint));

            LogInfo($"Requesting challenge from {challengeEndpoint}");
            try
            {
                using var client = new HttpClient();
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var response = await client.GetAsync(challengeEndpoint, cts.Token);
                response.EnsureSuccessStatusCode();
                var raw = await response.Content.ReadAsStringAsync();
                var challenge = JsonUtility.FromJson<ChallengeResponse>(raw) ?? new ChallengeResponse();
                LogInfo($"Challenge received. expiresAt={challenge.expiresAt}");
                return challenge;
            }
            catch (Exception ex)
            {
                LogError($"GetChallengeAsync failed for {challengeEndpoint}: {ex.Message}");
                throw;
            }
        }

        public async Task<DeviceRiskProfile> CollectAsync(CollectOptions opts)
        {
            opts ??= new CollectOptions();
            if (opts.collectedAtEpochMs <= 0)
            {
                opts.collectedAtEpochMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            }

            LogInfo($"CollectAsync start timeoutMs={opts.timeoutMs}, sampleCount={opts.sampleCount}, sensorDurationMs={opts.sensorDurationMs}, enableWidevine={opts.enableWidevine}, enableAudit={opts.enableAudit}, hasNonce={!string.IsNullOrWhiteSpace(opts.nonceB64)}");
#if UNITY_ANDROID && !UNITY_EDITOR
            // Capture Unity API values on current (main) thread; bridge must run on main thread for UnityPlayer.currentActivity
            var appVersion = GetAppVersionSafe();
            var unityVersion = GetUnityVersionSafe();
            var deviceModel = GetDeviceModelSafe();

            using (var bridge = new AndroidJavaClass(BridgeClass))
            {
                var json = JsonUtility.ToJson(opts);
                var resultJson = SafeCallCollect(bridge, json, out var bridgeCallErrorCode);
                if (bridgeCallErrorCode != null)
                {
                    return BuildCollectFallbackProfile(opts, bridgeCallErrorCode, appVersion, unityVersion, deviceModel);
                }

                var result = JsonUtility.FromJson<DeviceRiskProfile>(resultJson);
                if (result == null)
                {
                    LogError($"CollectAsync returned invalid JSON payload. rawLength={resultJson?.Length ?? 0}");
                    return BuildCollectFallbackProfile(opts, "COLLECT_RESULT_PARSE_FAILED", appVersion, unityVersion, deviceModel);
                }

                if (result.collectionMeta == null)
                {
                    result.collectionMeta = new CollectionMeta
                    {
                        errorCodes = new List<string> { "COLLECT_META_MISSING" },
                        nonceB64 = opts.nonceB64,
                        collectedAtEpochMs = opts.collectedAtEpochMs
                    };
                }
                else
                {
                    result.collectionMeta.errorCodes ??= new List<string>();
                    if (result.collectionMeta.collectedAtEpochMs <= 0)
                    {
                        result.collectionMeta.collectedAtEpochMs = opts.collectedAtEpochMs;
                    }

                    if (string.IsNullOrEmpty(result.collectionMeta.nonceB64))
                    {
                        result.collectionMeta.nonceB64 = opts.nonceB64;
                    }
                }

                LogInfo($"CollectAsync completed score={result.localRiskScore}, action={result.suggestedAction}, totalMs={result.collectionMeta.totalMs}");
                return result;
            }
#else
            await Task.Delay(1);
            LogWarning("CollectAsync running in non-Android/editor mode; returning PLATFORM_UNSUPPORTED fallback profile.");
            return BuildCollectFallbackProfile(opts, "PLATFORM_UNSUPPORTED");
#endif
        }

        public async Task<ServerVerdict> VerifyWithServerAsync(DeviceRiskProfile profile, Uri endpoint)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            if (endpoint == null) throw new ArgumentNullException(nameof(endpoint));

            var cacheKey = BuildCacheKey(profile, endpoint);
            var nowEpochMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (VerdictCache.TryGetValue(cacheKey, out var cached) && cached.ExpiresAtEpochMs > nowEpochMs)
            {
                LogInfo($"VerifyWithServerAsync cache hit for {endpoint}. expiresInMs={cached.ExpiresAtEpochMs - nowEpochMs}");
                return CloneVerdict(cached.Verdict);
            }

            LogInfo($"VerifyWithServerAsync cache miss. Sending request to {endpoint}");
            var requestDto = BuildVerifyRequestDto(profile);

            try
            {
                using var client = new HttpClient();
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var body = JsonUtility.ToJson(requestDto);
                var content = new StringContent(body, Encoding.UTF8, "application/json");
                var response = await client.PostAsync(endpoint, content, cts.Token);
                var raw = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    LogError($"VerifyWithServerAsync failed for {endpoint}: {(int)response.StatusCode} ({response.ReasonPhrase}). Body: {raw}");
                    var parsed = ParseVerdictResponse(raw);
                    if (!string.IsNullOrEmpty(parsed?.verdict))
                        return parsed;
                    return new ServerVerdict
                    {
                        verdict = "ERROR",
                        riskScore = -1,
                        reasonCodes = new List<string> { $"HTTP_{(int)response.StatusCode}" },
                        ttlSeconds = 0,
                        rawJson = raw
                    };
                }

                var verdict = ParseVerdictResponse(raw) ?? new ServerVerdict();
                verdict.rawJson = raw;

                if (verdict.ttlSeconds > 0)
                {
                    VerdictCache[cacheKey] = new CachedVerdict
                    {
                        ExpiresAtEpochMs = nowEpochMs + (long)verdict.ttlSeconds * 1000L,
                        Verdict = CloneVerdict(verdict)
                    };
                }

                LogInfo($"VerifyWithServerAsync completed verdict={verdict.verdict}, risk={verdict.riskScore}, ttlSeconds={verdict.ttlSeconds}");
                return verdict;
            }
            catch (Exception ex)
            {
                LogError($"VerifyWithServerAsync failed for {endpoint}: {ex.Message}");
                throw;
            }
        }

        /// <summary>Builds a DTO matching server verifyRequestSchema (ServerProject): non-empty app strings, ids "" or 64 hex, arrays never null.</summary>
        private static VerifyRequestDto BuildVerifyRequestDto(DeviceRiskProfile profile)
        {
            return new VerifyRequestDto
            {
                app = SanitizeApp(profile?.app),
                attestation = ToAttestationDto(profile?.keystoreAttestation, profile?.collectionMeta?.nonceB64),
                ids = new IdSection
                {
                    widevineIdSha256 = CoerceIdHash(profile?.widevineIdSha256),
                    sensorFingerprintSha256 = CoerceIdHash(profile?.sensorFingerprintSha256)
                },
                audit = ToAuditDto(profile?.environmentAudit),
                clientScore = new ClientScoreSection
                {
                    localRiskScore = Math.Max(0, Math.Min(100, profile?.localRiskScore ?? 0)),
                    suggestedAction = CoerceSuggestedAction(profile?.suggestedAction)
                },
                meta = ToMetaDto(profile?.collectionMeta)
            };
        }

        /// <summary>Server requires app.* strings min(1). Build fields (hardware, device, board, product) used by server for device fingerprint with IP.</summary>
        private static AppInfo SanitizeApp(AppInfo app)
        {
            const string fallback = "Unknown";
            const string emptyOk = "";
            if (app == null)
                return new AppInfo { appVersion = fallback, unityVersion = fallback, buildFingerprint = fallback, manufacturer = fallback, model = fallback, hardware = emptyOk, device = emptyOk, board = emptyOk, product = emptyOk };
            return new AppInfo
            {
                appVersion = string.IsNullOrEmpty(app.appVersion) ? fallback : app.appVersion,
                unityVersion = string.IsNullOrEmpty(app.unityVersion) ? fallback : app.unityVersion,
                buildFingerprint = string.IsNullOrEmpty(app.buildFingerprint) ? fallback : app.buildFingerprint,
                manufacturer = string.IsNullOrEmpty(app.manufacturer) ? fallback : app.manufacturer,
                model = string.IsNullOrEmpty(app.model) ? fallback : app.model,
                hardware = app.hardware ?? emptyOk,
                device = app.device ?? emptyOk,
                board = app.board ?? emptyOk,
                product = app.product ?? emptyOk
            };
        }

        /// <summary>Server expects 64 hex chars or "".</summary>
        private static string CoerceIdHash(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            if (value.Length != 64) return "";
            for (var i = 0; i < value.Length; i++)
            {
                var c = value[i];
                if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) return "";
            }
            return value;
        }

        private static string CoerceSuggestedAction(string value)
        {
            if (value == "ALLOW" || value == "FRICTION" || value == "RESTRICT" || value == "BLOCK") return value;
            return "ALLOW";
        }

        /// <summary>Server requires attestation; certChainB64 must be array (can be empty).</summary>
        private static KeystoreAttestationDto ToAttestationDto(KeystoreAttestation a, string fallbackChallengeB64)
        {
            var challengeB64 = (a != null && !string.IsNullOrEmpty(a.challengeB64)) ? a.challengeB64 : (fallbackChallengeB64 ?? "");
            var certChainB64 = (a?.certChainB64 != null && a.certChainB64.Count > 0) ? a.certChainB64.ToArray() : new string[0];
            return new KeystoreAttestationDto
            {
                challengeB64 = challengeB64,
                certChainB64 = certChainB64,
                errorCode = a?.errorCode
            };
        }

        /// <summary>Server requires audit with findings array (can be empty).</summary>
        private static EnvironmentAuditDto ToAuditDto(EnvironmentAudit a)
        {
            if (a == null)
                return new EnvironmentAuditDto { rootScore = 0, hookScore = 0, virtScore = 0, tamperScore = 0, findings = new string[0], errorCode = null };
            return new EnvironmentAuditDto
            {
                rootScore = a.rootScore,
                hookScore = a.hookScore,
                virtScore = a.virtScore,
                tamperScore = a.tamperScore,
                findings = a.findings != null && a.findings.Count > 0 ? a.findings.ToArray() : new string[0],
                errorCode = a.errorCode
            };
        }

        private static CollectionMetaDto ToMetaDto(CollectionMeta m)
        {
            if (m == null) return null;
            return new CollectionMetaDto
            {
                totalMs = m.totalMs,
                keystoreMs = m.keystoreMs,
                widevineMs = m.widevineMs,
                sensorMs = m.sensorMs,
                auditMs = m.auditMs,
                errorCodes = m.errorCodes != null ? m.errorCodes.ToArray() : null,
                nonceB64 = m.nonceB64 ?? "",
                collectedAtEpochMs = m.collectedAtEpochMs < 0 ? 0 : m.collectedAtEpochMs
            };
        }

        public async Task<SelfTestResult> SelfTestAsync(int timeoutMs = 4000)
        {
            LogInfo($"SelfTestAsync start timeoutMs={timeoutMs}");
#if UNITY_ANDROID && !UNITY_EDITOR
            return await Task.Run(() =>
            {
                using var bridge = new AndroidJavaClass(BridgeClass);
                var resultJson = bridge.CallStatic<string>("selfTest", timeoutMs);
                var result = JsonUtility.FromJson<SelfTestResult>(resultJson);
                LogInfo($"SelfTestAsync completed totalMs={result?.totalMs}, errorCount={result?.errorCodes?.Count ?? 0}");
                return result;
            });
#else
            await Task.Delay(1);
            LogWarning("SelfTestAsync running in non-Android/editor mode; returning PLATFORM_UNSUPPORTED.");
            return new SelfTestResult { errorCodes = new List<string> { "PLATFORM_UNSUPPORTED" }, timingsMs = new List<TimingEntry>() };
#endif
        }



        private static string SafeCallCollect(AndroidJavaClass bridge, string json, out string bridgeCallErrorCode)
        {
            bridgeCallErrorCode = null;
            const int maxAttempts = 2;

            for (var attempt = 1; attempt <= maxAttempts; attempt++)
            {
                try
                {
                    var resultJson = bridge.CallStatic<string>("collect", json);
                    if (!string.IsNullOrWhiteSpace(resultJson))
                    {
                        return resultJson;
                    }

                    LogWarning($"CollectAsync bridge returned empty payload on attempt {attempt}/{maxAttempts}.");
                }
                catch (AndroidJavaException ex)
                {
                    LogError($"CollectAsync Android bridge exception on attempt {attempt}/{maxAttempts}: {ex.Message}");
                    bridgeCallErrorCode = "COLLECT_BRIDGE_EXCEPTION";
                    return null;
                }
                catch (Exception ex)
                {
                    LogError($"CollectAsync bridge call failed on attempt {attempt}/{maxAttempts}: {ex.Message}");
                    bridgeCallErrorCode = "COLLECT_BRIDGE_CALL_FAILED";
                    return null;
                }

                if (attempt < maxAttempts)
                {
                    Thread.Sleep(80);
                }
            }

            bridgeCallErrorCode = "COLLECT_BRIDGE_EMPTY_RESULT";
            LogError("CollectAsync bridge returned empty payload after retries.");
            return null;
        }

        private static string GetAppVersionSafe()
        {
            try { return Application.version ?? ""; } catch { return ""; }
        }

        private static string GetUnityVersionSafe()
        {
            try { return Application.unityVersion ?? ""; } catch { return ""; }
        }

        private static string GetDeviceModelSafe()
        {
            try { return SystemInfo.deviceModel ?? ""; } catch { return ""; }
        }

        private static DeviceRiskProfile BuildCollectFallbackProfile(CollectOptions opts, string errorCode, string appVersion = null, string unityVersion = null, string deviceModel = null)
        {
            return new DeviceRiskProfile
            {
                app = new AppInfo
                {
                    appVersion = appVersion ?? GetAppVersionSafe(),
                    unityVersion = unityVersion ?? GetUnityVersionSafe(),
                    buildFingerprint = "editor",
                    manufacturer = "",
                    model = deviceModel ?? GetDeviceModelSafe()
                },
                collectionMeta = new CollectionMeta
                {
                    errorCodes = new List<string> { errorCode },
                    nonceB64 = opts?.nonceB64,
                    collectedAtEpochMs = opts?.collectedAtEpochMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                },
                localRiskScore = 100,
                suggestedAction = "BLOCK"
            };
        }

        private static string BuildCacheKey(DeviceRiskProfile profile, Uri endpoint)
        {
            var appVersion = profile.app?.appVersion ?? string.Empty;
            var widevine = profile.widevineIdSha256 ?? string.Empty;
            var sensor = profile.sensorFingerprintSha256 ?? string.Empty;
            return $"{endpoint}|{appVersion}|{widevine}|{sensor}";
        }

        private static ServerVerdict CloneVerdict(ServerVerdict source)
        {
            return new ServerVerdict
            {
                verdict = source.verdict,
                riskScore = source.riskScore,
                reasonCodes = source.reasonCodes != null ? new List<string>(source.reasonCodes) : new List<string>(),
                ttlSeconds = source.ttlSeconds,
                rawJson = source.rawJson
            };
        }

        /// <summary>Parse server JSON into ServerVerdict; uses array DTO so JsonUtility fills reasonCodes.</summary>
        private static ServerVerdict ParseVerdictResponse(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            try
            {
                var dto = JsonUtility.FromJson<ServerVerdictDto>(raw);
                if (dto == null) return null;
                return new ServerVerdict
                {
                    verdict = dto.verdict,
                    riskScore = dto.riskScore,
                    reasonCodes = dto.reasonCodes != null ? new List<string>(dto.reasonCodes) : new List<string>(),
                    ttlSeconds = dto.ttlSeconds,
                    rawJson = raw
                };
            }
            catch { return null; }
        }

        private static void LogInfo(string message) => Debug.Log($"{LogTag} {message}");
        private static void LogWarning(string message) => Debug.LogWarning($"{LogTag} {message}");
        private static void LogError(string message) => Debug.LogError($"{LogTag} {message}");

        private sealed class CachedVerdict
        {
            public long ExpiresAtEpochMs;
            public ServerVerdict Verdict;
        }

        [Serializable]
        private class ServerVerdictDto
        {
            public string verdict;
            public int riskScore;
            public string[] reasonCodes;
            public int ttlSeconds;
        }

        [Serializable]
        private class VerifyRequestDto
        {
            public AppInfo app;
            public KeystoreAttestationDto attestation;
            public IdSection ids;
            public EnvironmentAuditDto audit;
            public ClientScoreSection clientScore;
            public CollectionMetaDto meta;
        }

        [Serializable]
        private class KeystoreAttestationDto
        {
            public string challengeB64;
            public string[] certChainB64;
            public string errorCode;
        }

        [Serializable]
        private class EnvironmentAuditDto
        {
            public int rootScore;
            public int hookScore;
            public int virtScore;
            public int tamperScore;
            public string[] findings;
            public string errorCode;
        }

        [Serializable]
        private class CollectionMetaDto
        {
            public int totalMs;
            public int keystoreMs;
            public int widevineMs;
            public int sensorMs;
            public int auditMs;
            public string[] errorCodes;
            public string nonceB64;
            public long collectedAtEpochMs;
        }

        [Serializable]
        private class IdSection
        {
            public string widevineIdSha256;
            public string sensorFingerprintSha256;
        }

        [Serializable]
        private class ClientScoreSection
        {
            public int localRiskScore;
            public string suggestedAction;
        }
    }
}
