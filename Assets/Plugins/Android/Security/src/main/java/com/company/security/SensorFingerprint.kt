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

    fun collect(context: Context, targetSamples: Int, durationMs: Int): SensorResult {
        val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
        val accel = sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
        val gyro = sensorManager.getDefaultSensor(Sensor.TYPE_GYROSCOPE)
        if (accel == null || gyro == null) {
            Log.w(TAG, "collect sensors missing accel=${accel != null} gyro=${gyro != null}")
            return SensorResult(errorCode = "SENSOR_NOT_AVAILABLE")
        }

        val latch = CountDownLatch(1)
        val accSamples = mutableListOf<FloatArray>()
        val gyroSamples = mutableListOf<FloatArray>()

        Log.i(TAG, "collect start targetSamples=$targetSamples durationMs=$durationMs")

        val listener = object : SensorEventListener {
            override fun onSensorChanged(event: SensorEvent) {
                when (event.sensor.type) {
                    Sensor.TYPE_ACCELEROMETER -> accSamples.add(floatArrayOf(event.values[0], event.values[1], event.values[2]))
                    Sensor.TYPE_GYROSCOPE -> gyroSamples.add(floatArrayOf(event.values[0], event.values[1], event.values[2]))
                }
                if (accSamples.size >= targetSamples && gyroSamples.size >= targetSamples) {
                    latch.countDown()
                }
            }

            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) = Unit
        }

        sensorManager.registerListener(listener, accel, SensorManager.SENSOR_DELAY_GAME)
        sensorManager.registerListener(listener, gyro, SensorManager.SENSOR_DELAY_GAME)

        val completed = latch.await(durationMs.toLong(), TimeUnit.MILLISECONDS)
        sensorManager.unregisterListener(listener)

        if (accSamples.size < 20 || gyroSamples.size < 20) {
            val samples = minOf(accSamples.size, gyroSamples.size)
            Log.w(TAG, "collect insufficient samples=$samples completed=$completed")
            return SensorResult(sampleCount = samples, errorCode = "SENSOR_NOT_AVAILABLE")
        }

        val features = mutableListOf<Int>()
        features += extractFeatures(accSamples)
        features += extractFeatures(gyroSamples)

        val stableAcc = accSamples.take(40)
        val gravityMagnitude = stableAcc.map { v -> kotlin.math.sqrt((v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).toDouble()) }
        val gravMean = gravityMagnitude.average()
        features += (gravMean * 1000).roundToInt()
        features += if (completed) 1 else 0

        val raw = features.joinToString("|")
        val hash = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray())
            .joinToString("") { "%02x".format(it) }

        val totalSamples = minOf(accSamples.size, gyroSamples.size)
        Log.i(TAG, "collect success samples=$totalSamples completed=$completed")
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

        return listOf(mx, my, mz, vx, vy, vz, cxy, cyz, czx).map { (it * 10000.0).roundToInt() }
    }

    private fun variance(values: List<Double>, mean: Double): Double {
        return values.fold(0.0) { acc, d -> acc + (d - mean) * (d - mean) } / values.size
    }

    private fun covariance(a: List<Double>, b: List<Double>, ma: Double, mb: Double): Double {
        var sum = 0.0
        for (i in a.indices) {
            sum += (a[i] - ma) * (b[i] - mb)
        }
        return sum / a.size
    }
}
