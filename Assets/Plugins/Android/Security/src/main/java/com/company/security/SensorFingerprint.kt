package com.company.security

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.util.Log
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.math.roundToInt

internal data class SensorResult(
    val hashSha256: String? = null,
    val sampleCount: Int = 0,
    val errorCode: String? = null
)

internal object SensorFingerprint {
    private const val TAG = "SensorFingerprint"
    private const val SENSOR_SET_ACCEL_ONLY = "ACCEL_ONLY"
    private const val SENSOR_SET_ACCEL_GYRO = "ACCEL_GYRO"

    fun collect(context: Context, targetSamples: Int, durationMs: Int): SensorResult {
        val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
        val accel = sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
        val gyro = sensorManager.getDefaultSensor(Sensor.TYPE_GYROSCOPE)
        if (accel == null) {
            Log.w(TAG, "collect accelerometer missing")
            return SensorResult(errorCode = "SENSOR_NOT_AVAILABLE")
        }

        val gyroEnabled = gyro != null
        val latch = CountDownLatch(1)
        val accSamples = mutableListOf<FloatArray>()
        val gyroSamples = mutableListOf<FloatArray>()

        Log.i(TAG, "collect start targetSamples=$targetSamples durationMs=$durationMs gyroEnabled=$gyroEnabled")

        val listener = object : SensorEventListener {
            override fun onSensorChanged(event: SensorEvent) {
                when (event.sensor.type) {
                    Sensor.TYPE_ACCELEROMETER -> accSamples.add(floatArrayOf(event.values[0], event.values[1], event.values[2]))
                    Sensor.TYPE_GYROSCOPE -> if (gyroEnabled) gyroSamples.add(floatArrayOf(event.values[0], event.values[1], event.values[2]))
                }

                val accelReady = accSamples.size >= targetSamples
                val gyroReady = !gyroEnabled || gyroSamples.size >= targetSamples
                if (accelReady && gyroReady) {
                    latch.countDown()
                }
            }

            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) = Unit
        }

        sensorManager.registerListener(listener, accel, SensorManager.SENSOR_DELAY_GAME)
        if (gyroEnabled) {
            sensorManager.registerListener(listener, gyro, SensorManager.SENSOR_DELAY_GAME)
        }

        val completed = latch.await(durationMs.toLong(), TimeUnit.MILLISECONDS)
        sensorManager.unregisterListener(listener)

        if (accSamples.size < 20) {
            Log.w(TAG, "collect insufficient accelerometer samples=${accSamples.size} completed=$completed")
            return SensorResult(sampleCount = accSamples.size, errorCode = "SENSOR_NOT_AVAILABLE")
        }

        val sensorSet = if (gyroEnabled && gyroSamples.size >= 20) SENSOR_SET_ACCEL_GYRO else SENSOR_SET_ACCEL_ONLY
        val usedGyro = sensorSet == SENSOR_SET_ACCEL_GYRO

        val features = mutableListOf<Int>()
        features += extractFeatures(accSamples)
        if (usedGyro) {
            features += extractFeatures(gyroSamples)
        }

        val stableAcc = accSamples.take(40)
        val gravityMagnitude = stableAcc.map { v -> kotlin.math.sqrt((v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).toDouble()) }
        val gravMean = gravityMagnitude.average()
        features += (gravMean * 1000).roundToInt()
        features += if (completed) 1 else 0

        val raw = buildString {
            append("sensorSet=")
            append(sensorSet)
            append('|')
            append(features.joinToString("|"))
        }

        val hash = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray())
            .joinToString("") { "%02x".format(it) }

        val totalSamples = if (usedGyro) minOf(accSamples.size, gyroSamples.size) else accSamples.size
        Log.i(TAG, "collect success samples=$totalSamples completed=$completed sensorSet=$sensorSet")
        return SensorResult(hashSha256 = hash, sampleCount = totalSamples)
    }

    private fun extractFeatures(samples: List<FloatArray>): List<Int> {
        val x = samples.map { it[0].toDouble() }
        val y = samples.map { it[1].toDouble() }
        val z = samples.map { it[2].toDouble() }

        val mx = x.average()
        val my = y.average()
        val mz = z.average()
        val vx = variance(x, mx)
        val vy = variance(y, my)
        val vz = variance(z, mz)
        val cxy = covariance(x, y, mx, my)
        val cyz = covariance(y, z, my, mz)
        val czx = covariance(z, x, mz, mx)

        return listOf(mx, my, mz, vx, vy, vz, cxy, cyz, czx).map { (it * 1000.0).roundToInt() }
    }

    private fun variance(values: List<Double>, mean: Double): Double {
        if (values.isEmpty()) return 0.0
        var acc = 0.0
        for (v in values) {
            val d = v - mean
            acc += d * d
        }
        return acc / values.size.toDouble()
    }

    private fun covariance(a: List<Double>, b: List<Double>, ma: Double, mb: Double): Double {
        if (a.isEmpty() || b.isEmpty()) return 0.0
        val n = minOf(a.size, b.size)
        if (n == 0) return 0.0
        var acc = 0.0
        for (i in 0 until n) {
            acc += (a[i] - ma) * (b[i] - mb)
        }
        return acc / n.toDouble()
    }
}
