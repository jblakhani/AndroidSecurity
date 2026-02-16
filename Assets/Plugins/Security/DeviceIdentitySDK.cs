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
            return await Task.Run(() =>
            {
                using var bridge = new AndroidJavaClass(BridgeClass);
                var json = JsonUtility.ToJson(opts);
                var resultJson = bridge.CallStatic<string>("collect", json);
                var result = JsonUtility.FromJson<DeviceRiskProfile>(resultJson);
                LogInfo($"CollectAsync completed score={result?.localRiskScore}, action={result?.suggestedAction}, totalMs={result?.collectionMeta?.totalMs}");
                return result;
            });
#else
            await Task.Delay(1);
            var fallback = new DeviceRiskProfile
            {
                app = new AppInfo
                {
                    appVersion = Application.version,
                    unityVersion = Application.unityVersion,
                    buildFingerprint = "editor",
                    manufacturer = SystemInfo.deviceManufacturer,
                    model = SystemInfo.deviceModel
                },
                collectionMeta = new CollectionMeta { errorCodes = new List<string> { "PLATFORM_UNSUPPORTED" }, nonceB64 = opts.nonceB64, collectedAtEpochMs = opts.collectedAtEpochMs },
                localRiskScore = 100,
                suggestedAction = "BLOCK"
            };
            LogWarning("CollectAsync running in non-Android/editor mode; returning PLATFORM_UNSUPPORTED fallback profile.");
            return fallback;
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
            var request = new VerifyRequest
            {
                app = profile.app,
                attestation = profile.keystoreAttestation,
                ids = new IdSection
                {
                    widevineIdSha256 = profile.widevineIdSha256,
                    sensorFingerprintSha256 = profile.sensorFingerprintSha256
                },
                audit = profile.environmentAudit,
                clientScore = new ClientScoreSection
                {
                    localRiskScore = profile.localRiskScore,
                    suggestedAction = profile.suggestedAction
                },
                meta = profile.collectionMeta
            };

            try
            {
                using var client = new HttpClient();
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var body = JsonUtility.ToJson(request);
                var content = new StringContent(body, Encoding.UTF8, "application/json");
                var response = await client.PostAsync(endpoint, content, cts.Token);
                response.EnsureSuccessStatusCode();
                var raw = await response.Content.ReadAsStringAsync();
                var verdict = JsonUtility.FromJson<ServerVerdict>(raw) ?? new ServerVerdict();
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

        private static void LogInfo(string message) => Debug.Log($"{LogTag} {message}");
        private static void LogWarning(string message) => Debug.LogWarning($"{LogTag} {message}");
        private static void LogError(string message) => Debug.LogError($"{LogTag} {message}");

        private sealed class CachedVerdict
        {
            public long ExpiresAtEpochMs;
            public ServerVerdict Verdict;
        }

        [Serializable]
        private class VerifyRequest
        {
            public AppInfo app;
            public KeystoreAttestation attestation;
            public IdSection ids;
            public EnvironmentAudit audit;
            public ClientScoreSection clientScore;
            public CollectionMeta meta;
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
