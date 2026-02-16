using System;
using System.Collections.Generic;

namespace Company.Security.Models
{
    [Serializable]
    public class CollectOptions
    {
        public int sampleCount = 200;
        public int sensorDurationMs = 1500;
        public bool enableWidevine = true;
        public bool enableAudit = true;
        public int timeoutMs = 4000;
        public bool selfTest = false;
    }

    [Serializable]
    public class AppInfo
    {
        public string appVersion;
        public string unityVersion;
        public string buildFingerprint;
        public string manufacturer;
        public string model;
    }

    [Serializable]
    public class KeystoreAttestation
    {
        public string challengeB64;
        public List<string> certChainB64;
        public string errorCode;
    }

    [Serializable]
    public class EnvironmentAudit
    {
        public int rootScore;
        public int hookScore;
        public int virtScore;
        public int tamperScore;
        public List<string> findings;
        public string errorCode;
    }

    [Serializable]
    public class CollectionMeta
    {
        public int totalMs;
        public int keystoreMs;
        public int widevineMs;
        public int sensorMs;
        public int auditMs;
        public List<string> errorCodes;
    }

    [Serializable]
    public class DeviceRiskProfile
    {
        public AppInfo app;
        public KeystoreAttestation keystoreAttestation;
        public string widevineIdSha256;
        public string sensorFingerprintSha256;
        public EnvironmentAudit environmentAudit;
        public int localRiskScore;
        public string suggestedAction;
        public CollectionMeta collectionMeta;
    }

    [Serializable]
    public class ServerVerdict
    {
        public string verdict;
        public int riskScore;
        public List<string> reasonCodes;
        public int ttlSeconds;
        public string rawJson;
    }

    [Serializable]
    public class SelfTestResult
    {
        public bool keystoreAvailable;
        public bool widevineAvailable;
        public bool accelerometerAvailable;
        public bool gyroAvailable;
        public bool procReadable;
        public int totalMs;
        public Dictionary<string, int> timingsMs;
        public List<string> errorCodes;
    }
}
