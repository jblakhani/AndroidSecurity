package com.company.security

import android.content.Context
import android.os.Build
import com.unity3d.player.UnityPlayer
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class DeviceIdentityBridge {
    companion object {
        private const val PREFS_NAME = "device_identity_sdk"
        private const val SENSOR_MAP_PREFIX = "sensor_map_"

        @JvmStatic
        fun collect(optionsJson: String): String {
            val options = parseOptions(optionsJson)
            val context = UnityPlayer.currentActivity.applicationContext
            val startTotal = System.nanoTime()
            val errors = mutableListOf<String>()

            val executor = Executors.newSingleThreadExecutor()
            return try {
                val task = Callable {
                    val timings = mutableMapOf<String, Int>()

                    val app = JSONObject()
                        .put("appVersion", appVersion(context))
                        .put("unityVersion", UnityPlayer.unityVersion)
                        .put("buildFingerprint", Build.FINGERPRINT ?: "")
                        .put("manufacturer", Build.MANUFACTURER ?: "")
                        .put("model", Build.MODEL ?: "")

                    val ksStart = nowMs()
                    val ks = KeystoreAttestation.attest(options.nonceB64)
                    timings["keystoreMs"] = nowMs() - ksStart
                    ks.errorCode?.let { errors += it }

                    val widevineStart = nowMs()
                    val wv = if (options.enableWidevine) WidevineId.collectHash() else WidevineResult(errorCode = "WIDEVINE_UNSUPPORTED")
                    timings["widevineMs"] = nowMs() - widevineStart
                    wv.errorCode?.let { errors += it }

                    val sensorStart = nowMs()
                    val sf = SensorFingerprint.collect(context, options.sampleCount, options.sensorDurationMs)
                    timings["sensorMs"] = nowMs() - sensorStart
                    sf.errorCode?.let { errors += it }

                    val anomalyWidevineChangedSensorStable = detectAndPersistWidevineSensorAnomaly(
                        context = context,
                        widevineHash = wv.hashSha256,
                        sensorHash = sf.hashSha256
                    )

                    val auditStart = nowMs()
                    val audit = if (options.enableAudit) EnvironmentAudit.run() else EnvironmentAuditResult(0, 0, 0, 0, emptyList())
                    timings["auditMs"] = nowMs() - auditStart
                    audit.errorCode?.let { errors += it }

                    val score = score(ks, wv, sf, audit, anomalyWidevineChangedSensorStable)
                    val action = actionFor(score, audit)

                    val meta = JSONObject()
                        .put("totalMs", ((System.nanoTime() - startTotal) / 1_000_000L).toInt())
                        .put("keystoreMs", timings["keystoreMs"] ?: 0)
                        .put("widevineMs", timings["widevineMs"] ?: 0)
                        .put("sensorMs", timings["sensorMs"] ?: 0)
                        .put("auditMs", timings["auditMs"] ?: 0)
                        .put("errorCodes", JSONArray(errors.sorted()))
                        .put("nonceB64", options.nonceB64)
                        .put("collectedAtEpochMs", options.collectedAtEpochMs)

                    JSONObject()
                        .put("app", app)
                        .put("keystoreAttestation", JSONObject()
                            .put("challengeB64", ks.challengeB64)
                            .put("certChainB64", JSONArray(ks.certChainB64))
                            .put("errorCode", ks.errorCode ?: JSONObject.NULL)
                        )
                        .put("widevineIdSha256", wv.hashSha256 ?: "")
                        .put("sensorFingerprintSha256", sf.hashSha256 ?: "")
                        .put("environmentAudit", JSONObject()
                            .put("rootScore", audit.rootScore)
                            .put("hookScore", audit.hookScore)
                            .put("virtScore", audit.virtScore)
                            .put("tamperScore", audit.tamperScore)
                            .put("findings", JSONArray(audit.findings.sorted()))
                            .put("errorCode", audit.errorCode ?: JSONObject.NULL)
                        )
                        .put("localRiskScore", score)
                        .put("suggestedAction", action)
                        .put("collectionMeta", meta)
                        .toString()
                }
                executor.submit(task).get(options.timeoutMs.toLong(), TimeUnit.MILLISECONDS)
            } catch (_: java.util.concurrent.TimeoutException) {
                JSONObject()
                    .put("localRiskScore", 100)
                    .put("suggestedAction", "BLOCK")
                    .put("collectionMeta", JSONObject()
                        .put("errorCodes", JSONArray(listOf("TIMEOUT")))
                        .put("totalMs", options.timeoutMs)
                        .put("nonceB64", options.nonceB64)
                        .put("collectedAtEpochMs", options.collectedAtEpochMs)
                    )
                    .toString()
            } catch (_: Exception) {
                JSONObject()
                    .put("localRiskScore", 100)
                    .put("suggestedAction", "BLOCK")
                    .put("collectionMeta", JSONObject()
                        .put("errorCodes", JSONArray(listOf("INTERNAL_EXCEPTION")))
                        .put("totalMs", nowMs())
                        .put("nonceB64", options.nonceB64)
                        .put("collectedAtEpochMs", options.collectedAtEpochMs)
                    )
                    .toString()
            } finally {
                executor.shutdownNow()
            }
        }

        @JvmStatic
        fun selfTest(timeoutMs: Int): String {
            val context = UnityPlayer.currentActivity.applicationContext
            val start = nowMs()
            val timingEntries = JSONArray()
            val errors = mutableListOf<String>()

            val ksStart = nowMs()
            val ks = KeystoreAttestation.attest(null)
            timingEntries.put(JSONObject().put("key", "keystoreMs").put("value", nowMs() - ksStart))
            ks.errorCode?.let { errors += it }

            val wvStart = nowMs()
            val wv = WidevineId.collectHash()
            timingEntries.put(JSONObject().put("key", "widevineMs").put("value", nowMs() - wvStart))
            wv.errorCode?.let { errors += it }

            val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as android.hardware.SensorManager
            val accel = sensorManager.getDefaultSensor(android.hardware.Sensor.TYPE_ACCELEROMETER) != null
            val gyro = sensorManager.getDefaultSensor(android.hardware.Sensor.TYPE_GYROSCOPE) != null
            val procReadable = try {
                java.io.File("/proc/self/maps").canRead()
            } catch (_: Exception) {
                errors += "PROC_READ_DENIED"
                false
            }

            return JSONObject()
                .put("keystoreAvailable", ks.errorCode == null)
                .put("widevineAvailable", wv.errorCode == null)
                .put("accelerometerAvailable", accel)
                .put("gyroAvailable", gyro)
                .put("procReadable", procReadable)
                .put("totalMs", (nowMs() - start).coerceAtMost(timeoutMs))
                .put("timingsMs", timingEntries)
                .put("errorCodes", JSONArray(errors.sorted()))
                .toString()
        }

        private fun parseOptions(optionsJson: String): CollectOptions {
            val j = try { JSONObject(optionsJson) } catch (_: Exception) { JSONObject() }
            val collectedAtEpochMs = j.optLong("collectedAtEpochMs", System.currentTimeMillis())
            return CollectOptions(
                sampleCount = j.optInt("sampleCount", 200).coerceIn(50, 500),
                sensorDurationMs = j.optInt("sensorDurationMs", 1500).coerceIn(400, 2500),
                enableWidevine = j.optBoolean("enableWidevine", true),
                enableAudit = j.optBoolean("enableAudit", true),
                timeoutMs = j.optInt("timeoutMs", 4000).coerceIn(1000, 4000),
                nonceB64 = j.optString("nonceB64", ""),
                collectedAtEpochMs = if (collectedAtEpochMs > 0) collectedAtEpochMs else System.currentTimeMillis()
            )
        }

        private fun score(
            ks: KeystoreResult,
            wv: WidevineResult,
            sf: SensorResult,
            audit: EnvironmentAuditResult,
            widevineChangedSensorStable: Boolean
        ): Int {
            var score = 0
            if (ks.errorCode != null) score += 50
            if (wv.errorCode != null) score += 25
            if (sf.errorCode != null) score += 15
            if (audit.hookScore >= 18) score += 40
            if (audit.rootScore >= 15) score += 30
            if (audit.virtScore >= 15) score += 25
            if (widevineChangedSensorStable) score += 20
            return score.coerceAtMost(100)
        }

        private fun detectAndPersistWidevineSensorAnomaly(
            context: Context,
            widevineHash: String?,
            sensorHash: String?
        ): Boolean {
            if (widevineHash.isNullOrBlank() || sensorHash.isNullOrBlank()) {
                return false
            }

            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val key = "$SENSOR_MAP_PREFIX$sensorHash"
            val previousWidevine = prefs.getString(key, null)
            val changed = previousWidevine != null && previousWidevine != widevineHash
            prefs.edit().putString(key, widevineHash).apply()
            return changed
        }

        private fun actionFor(score: Int, audit: EnvironmentAuditResult): String {
            val mediumSignals = listOf(audit.rootScore, audit.hookScore, audit.virtScore).count { it in 10..17 }
            return when {
                score >= 80 && mediumSignals <= 1 -> "BLOCK"
                score >= 60 -> "RESTRICT"
                score >= 30 -> "FRICTION"
                else -> "ALLOW"
            }
        }

        private fun appVersion(context: Context): String {
            return try {
                val pInfo = context.packageManager.getPackageInfo(context.packageName, 0)
                pInfo.versionName ?: pInfo.longVersionCode.toString()
            } catch (_: Exception) {
                ""
            }
        }

        private fun nowMs(): Int = (System.nanoTime() / 1_000_000L).toInt()
    }
}

private data class CollectOptions(
    val sampleCount: Int,
    val sensorDurationMs: Int,
    val enableWidevine: Boolean,
    val enableAudit: Boolean,
    val timeoutMs: Int,
    val nonceB64: String,
    val collectedAtEpochMs: Long
)
