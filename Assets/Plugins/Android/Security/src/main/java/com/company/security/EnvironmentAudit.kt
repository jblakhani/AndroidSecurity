package com.company.security

import android.os.Build
import android.util.Log
import java.io.File
import java.io.BufferedReader

internal data class EnvironmentAuditResult(
    val rootScore: Int,
    val hookScore: Int,
    val virtScore: Int,
    val tamperScore: Int,
    val findings: List<String>,
    val errorCode: String? = null
)

internal object EnvironmentAudit {
    private const val TAG = "EnvironmentAudit"

    fun run(): EnvironmentAuditResult {
        val findings = mutableListOf<String>()

        val rootScore = detectRoot(findings)
        val hookData = detectHooks(findings)
        val virtScore = detectVirtualization(findings)
        val tamperScore = detectTamper(findings)

        val result = EnvironmentAuditResult(
            rootScore = rootScore,
            hookScore = hookData.first,
            virtScore = virtScore,
            tamperScore = tamperScore,
            findings = findings,
            errorCode = hookData.second
        )

        Log.i(TAG, "run completed root=$rootScore hook=${hookData.first} virt=$virtScore tamper=$tamperScore error=${hookData.second}")
        return result
    }

    private fun detectRoot(findings: MutableList<String>): Int {
        var score = 0
        val suPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/vendor/bin/su",
            "/system/app/Superuser.apk", "/data/adb/magisk"
        )
        suPaths.filter { File(it).exists() }.forEach {
            score += 8
            findings += "root_path:$it"
        }

        val tags = Build.TAGS ?: ""
        if (tags.contains("test-keys")) {
            score += 10
            findings += "build_tags:test-keys"
        }

        val dbg = readProp("ro.debuggable")
        if (dbg == "1") {
            score += 7
            findings += "ro.debuggable=1"
        }

        val secure = readProp("ro.secure")
        if (secure == "0") {
            score += 7
            findings += "ro.secure=0"
        }

        return score.coerceAtMost(25)
    }

    private fun detectHooks(findings: MutableList<String>): Pair<Int, String?> {
        var score = 0
        var readError: String? = null
        try {
            val needles = listOf("frida", "xposed", "substrate", "riru", "zygisk", "edxp")
            var suspicious = 0
            var anonExec = 0

            File("/proc/self/maps").bufferedReader().use { reader: BufferedReader ->
                while (true) {
                    val line = reader.readLine() ?: break
                    val lc = line.lowercase()

                    if (needles.any { lc.contains(it) }) {
                        suspicious++
                        findings += "hook_map:${lc.take(120)}"
                    }

                    val parts = line.split(' ', limit = 6).filter { it.isNotEmpty() }
                    val perms = parts.getOrNull(1) ?: ""
                    val path = parts.getOrNull(5) ?: ""
                    if (perms.contains('x') && path.startsWith("[") && path.contains("anon", ignoreCase = true)) {
                        anonExec++
                    }

                    if (suspicious >= 3 && anonExec > 6) {
                        break
                    }
                }
            }

            if (suspicious > 0) score += 20
            if (anonExec > 6) {
                score += 10
                findings += "anon_exec_regions:$anonExec"
            }
        } catch (e: Exception) {
            readError = "PROC_READ_DENIED"
            findings += "proc_maps_unreadable"
            Log.w(TAG, "detectHooks unable to read /proc/self/maps: ${e.message}")
        }
        return Pair(score.coerceAtMost(25), readError)
    }

    private fun detectVirtualization(findings: MutableList<String>): Int {
        var score = 0
        val fp = Build.FINGERPRINT.lowercase()
        val model = Build.MODEL.lowercase()
        val brand = Build.BRAND.lowercase()

        if (fp.contains("generic") || fp.contains("emulator") || fp.contains("vbox") || fp.contains("test-keys")) {
            score += 12
            findings += "virt_fingerprint"
        }
        if (model.contains("sdk") || model.contains("emulator") || model.contains("x86")) {
            score += 8
            findings += "virt_model"
        }
        if (brand.contains("generic")) {
            score += 5
            findings += "virt_brand"
        }
        return score.coerceAtMost(25)
    }

    private fun detectTamper(findings: MutableList<String>): Int {
        var score = 0
        if (android.os.Debug.isDebuggerConnected() || android.os.Debug.waitingForDebugger()) {
            score += 15
            findings += "debugger_connected"
        }
        if (Build.TYPE.equals("userdebug", ignoreCase = true) || Build.TYPE.equals("eng", ignoreCase = true)) {
            score += 10
            findings += "build_type:${Build.TYPE}"
        }
        return score.coerceAtMost(25)
    }

    private fun readProp(name: String): String {
        return try {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            method.invoke(null, name) as? String ?: ""
        } catch (_: Exception) {
            ""
        }
    }
}
