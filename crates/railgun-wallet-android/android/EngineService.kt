package com.zknox.railgunwallet

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder

/**
 * Keeps the process alive while a sync, a proof or a broadcaster round trip is running. It owns
 * no logic: the engine thread and the js-waku node live in the app, this only stops Android from
 * killing them when the user leaves the screen.
 *
 * Start it from the front through a Tauri command when a job starts, stop it when the job list
 * goes idle. Android 15 caps `dataSync` at six hours per day, which is why it is not simply left
 * running (ADR-028).
 */
class EngineService : Service() {
    companion object {
        private const val CHANNEL = "railgun-engine"
        private const val ID = 1

        fun start(context: Context, text: String) {
            val intent = Intent(context, EngineService::class.java).putExtra("text", text)
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, EngineService::class.java))
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "Railgun wallet", NotificationManager.IMPORTANCE_LOW)
        )
        val text = intent?.getStringExtra("text") ?: "Working"
        val notification: Notification = Notification.Builder(this, CHANNEL)
            .setContentTitle("Railgun wallet")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .build()
        startForeground(ID, notification)
        return START_NOT_STICKY   // a restarted service without the engine behind it is a lie
    }
}
