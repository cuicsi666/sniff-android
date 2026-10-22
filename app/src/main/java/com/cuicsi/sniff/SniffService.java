package com.cuicsi.sniff;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

/** 前台服务：保证 tcpdump 在后台持续运行 */
public class SniffService extends Service {

    public static final String ACTION_START = "com.cuicsi.sniff.START";
    public static final String ACTION_STOP = "com.cuicsi.sniff.STOP";
    public static final String EXTRA_NAME = "name";
    public static final String EXTRA_FILTER = "filter";

    public static final String DIR = "/sdcard/RC抓包";
    private static final String PID_FILE = "/data/adb/sniff.pid";
    private static final String CHANNEL = "sniff";

    public static volatile boolean running = false;
    public static volatile String currentFile = "";
    public static volatile String currentFilter = "";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        startForegroundCompat();

        if (ACTION_STOP.equals(action)) {
            final boolean[] done = {false};
            new Thread(() -> {
                stopCapture();
                done[0] = true;
            }).start();
            for (int i = 0; i < 40 && !done[0]; i++) {
                try { Thread.sleep(100); } catch (InterruptedException ignored) { }
            }
            stopForeground(true);
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_START.equals(action)) {
            final String name = intent.getStringExtra(EXTRA_NAME);
            final String filter = intent.getStringExtra(EXTRA_FILTER);
            // 网络请求不能在主线程（NetworkOnMainThreadException）
            new Thread(() -> startCapture(name, filter)).start();
        }
        return START_STICKY;
    }

    private void startForegroundCompat() {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "抓包状态", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            nm.createNotificationChannel(ch);
        }
        Notification n = new NotificationCompat.Builder(this, CHANNEL)
                .setContentTitle("系统抓包运行中")
                .setContentText(currentFile.isEmpty() ? "正在捕获网络流量…" : currentFile)
                .setSmallIcon(R.drawable.ic_launcher)
                .setOngoing(true)
                .build();
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(1001, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(1001, n);
        }
    }

    private void startCapture(String name, String filter) {
        stopCapture();
        if (name == null || name.trim().isEmpty()) {
            name = "sniff_" + new java.text.SimpleDateFormat("MMdd_HHmmss", java.util.Locale.US).format(new java.util.Date());
        }
        name = name.replaceAll("[^a-zA-Z0-9_\\-\\u4e00-\\u9fa5]", "_");
        String file = DIR + "/" + name + ".pcap";
        String f = filter == null ? "" : filter.trim();
        currentFile = file;
        currentFilter = f;

        String cmd = "mkdir -p '" + DIR + "'; rm -f '" + file + "'; "
                + "nohup tcpdump -i any -s 0 -w '" + file + "' " + f
                + " >/data/adb/sniff.log 2>&1 & echo $! > " + PID_FILE;
        Root.Result r = Root.run(cmd, 15);
        running = true;
        startForegroundCompat();
    }

    private void stopCapture() {
        // 直接按命令行杀，pid 文件在 su 环境里可能对不上
        Root.run("pkill -2 -f 'tcpdump -i any' 2>/dev/null; sleep 1; "
                + "pkill -9 -f 'tcpdump -i any' 2>/dev/null; rm -f " + PID_FILE, 20);
        running = false;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
