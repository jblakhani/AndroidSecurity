package com.company.security

import android.media.MediaDrm
import java.security.MessageDigest
import java.util.UUID

internal data class WidevineResult(
    val hashSha256: String? = null,
    val errorCode: String? = null
)

internal object WidevineId {
    private val WIDEVINE_UUID: UUID = UUID(-0x121074568629b532L, -0x5c37d8232ae2de13L)

    fun collectHash(): WidevineResult {
        return try {
            val drm = MediaDrm(WIDEVINE_UUID)
            val raw = drm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID)
            val hashed = sha256Hex(raw)
            raw.fill(0)
            drm.release()
            WidevineResult(hashSha256 = hashed)
        } catch (unsupported: UnsupportedOperationException) {
            WidevineResult(errorCode = "WIDEVINE_UNSUPPORTED")
        } catch (_: Exception) {
            WidevineResult(errorCode = "WIDEVINE_EXCEPTION")
        }
    }

    private fun sha256Hex(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(data)
        return digest.joinToString("") { "%02x".format(it) }
    }
}
