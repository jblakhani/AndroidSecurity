using Company.Security;
using Company.Security.Models;
using System;
using TMPro;
using UnityEngine;

public class DeviceRiskBootstrap : MonoBehaviour
{
    [Tooltip("Base URL of the device-risk server (e.g. http://localhost:8080 in Editor). On a physical Android device use your PC's IP (e.g. http://192.168.1.82:8080) so the device can reach the server.")]
    [SerializeField] private string serverBaseUrl = "http://192.168.1.82:8080";

    private readonly DeviceIdentitySDK _sdk = new DeviceIdentitySDK();

    public TextMeshProUGUI TextMeshProUGUI;

    private void Start()
    {
        RunDeviceRiskFlow();
    }

    private async void RunDeviceRiskFlow()
    {
        string baseUrl = serverBaseUrl.TrimEnd('/');
        string challengeUrl = $"{baseUrl}/device/challenge";
        string verifyUrl = $"{baseUrl}/device/verify";

        var opts = new CollectOptions
        {
            sampleCount = 200,
            sensorDurationMs = 1500,
            enableWidevine = true,
            enableAudit = true,
            timeoutMs = 4000
        };

        try
        {
            ChallengeResponse challenge = await _sdk.GetChallengeAsync(new Uri(challengeUrl));
            if (challenge != null && !string.IsNullOrEmpty(challenge.nonceB64))
            {
                opts.nonceB64 = challenge.nonceB64;
            }

            DeviceRiskProfile profile = await _sdk.CollectAsync(opts);
            if (profile?.collectionMeta?.errorCodes?.Count > 0)
            {
                var t = $"[DeviceRiskBootstrap] Collect had errors: {string.Join(", ", profile.collectionMeta.errorCodes)}";
                TextMeshProUGUI.text = t ;
                Debug.LogWarning(t);
            }

            ServerVerdict verdict = await _sdk.VerifyWithServerAsync(profile, new Uri(verifyUrl));
            var y = $"[DeviceRiskBootstrap] ServerVerdict={verdict?.verdict}, Score={verdict?.riskScore ?? -1}";
            TextMeshProUGUI.text = y ;
            Debug.Log(y);
        }
        catch (Exception ex)
        {
            var z = $"[DeviceRiskBootstrap] Device risk flow failed: {ex.Message}\n{ex.StackTrace}";
            TextMeshProUGUI.text = z ;
            Debug.LogError(z);
        }
    }
}