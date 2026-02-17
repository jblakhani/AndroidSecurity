using UnityEditor.Android;
using System.IO;

namespace Company.Security.Editor
{
    /// <summary>
    /// Enables cleartext (HTTP) traffic for Android builds so the device-risk
    /// challenge/verify server can be reached at e.g. http://192.168.1.82:8080.
    /// Remove or disable for production if you use HTTPS only.
    /// </summary>
    public class AndroidCleartextEnabler : IPostGenerateGradleAndroidProject
    {
        public int callbackOrder => 0;

        public void OnPostGenerateGradleAndroidProject(string path)
        {
            string manifestPath = Path.Combine(path, "launcher", "src", "main", "AndroidManifest.xml");
            if (!File.Exists(manifestPath))
                return;

            string content = File.ReadAllText(manifestPath);
            if (content.IndexOf("usesCleartextTraffic", System.StringComparison.Ordinal) >= 0)
                return;

            const string applicationTag = "<application ";
            int idx = content.IndexOf(applicationTag, System.StringComparison.Ordinal);
            if (idx < 0)
                return;

            int insertAt = idx + applicationTag.Length;
            content = content.Insert(insertAt, "android:usesCleartextTraffic=\"true\" ");
            File.WriteAllText(manifestPath, content);
        }
    }
}
