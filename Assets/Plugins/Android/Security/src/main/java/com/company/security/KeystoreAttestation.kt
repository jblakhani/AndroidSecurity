package com.company.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

internal data class KeystoreResult(
    val challengeB64: String,
    val certChainB64: List<String>,
    val strongBoxUsed: Boolean,
    val errorCode: String? = null
)

internal object KeystoreAttestation {
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

    fun attest(challengeOverrideB64: String?, alias: String = "device_identity_attest"): KeystoreResult {
        val challenge = decodeOrRandomChallenge(challengeOverrideB64)
        val challengeB64 = Base64.encodeToString(challenge, Base64.NO_WRAP)

        return try {
            val strongBoxAttempt = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
            val result = generate(alias, challenge, strongBox = strongBoxAttempt)
            result ?: generate(alias, challenge, strongBox = false)
                ?: KeystoreResult(challengeB64, emptyList(), false, "KEYSTORE_ATTESTATION_FAILED")
        } catch (_: Exception) {
            KeystoreResult(challengeB64, emptyList(), false, "KEYSTORE_ATTESTATION_FAILED")
        }
    }

    private fun decodeOrRandomChallenge(challengeOverrideB64: String?): ByteArray {
        if (!challengeOverrideB64.isNullOrBlank()) {
            try {
                val decoded = Base64.decode(challengeOverrideB64, Base64.DEFAULT)
                if (decoded.size in 16..128) {
                    return decoded
                }
            } catch (_: Exception) {
                // fall through to random challenge generation
            }
        }
        val randomChallenge = ByteArray(32)
        SecureRandom().nextBytes(randomChallenge)
        return randomChallenge
    }

    private fun generate(alias: String, challenge: ByteArray, strongBox: Boolean): KeystoreResult? {
        return try {
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }

            val specBuilder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                specBuilder.setIsStrongBoxBacked(strongBox)
            }

            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                KEYSTORE_PROVIDER
            )
            keyPairGenerator.initialize(specBuilder.build())
            keyPairGenerator.generateKeyPair()

            val certs = keyStore.getCertificateChain(alias)
                ?.mapNotNull { cert ->
                    (cert as? X509Certificate)?.encoded?.let { Base64.encodeToString(it, Base64.NO_WRAP) }
                }
                ?: emptyList()

            if (certs.isEmpty()) {
                KeystoreResult(Base64.encodeToString(challenge, Base64.NO_WRAP), certs, strongBox, "KEYSTORE_ATTESTATION_FAILED")
            } else {
                KeystoreResult(Base64.encodeToString(challenge, Base64.NO_WRAP), certs, strongBox, null)
            }
        } catch (_: Exception) {
            null
        }
    }
}
