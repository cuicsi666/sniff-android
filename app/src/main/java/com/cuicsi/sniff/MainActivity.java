package com.cuicsi.sniff;

import android.Manifest;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.content.FileProvider;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class MainActivity extends AppCompatActivity {

    private static final String DIR = "/sdcard/RC抓包";
    private static final String PID_FILE = "/data/adb/sniff.pid";

    private TextView txtRoot, txtStatus, txtBadge, txtEmpty;
    private Spinner spFilter;
    private EditText edFilter, edName;
    private Button btnStart, btnStop;
    private ListView listFiles;

    private final List<Item> items = new ArrayList<>();
    private ItemAdapter adapter;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private boolean running = false;
    private boolean firstRootCheck = true;

    private final String[] filterLabels = {"全部流量", "HTTPS (443)", "HTTP (80)", "DNS (53)", "自定义"};
    private final String[] filterExprs = {"", "tcp port 443", "tcp port 80", "udp port 53 or tcp port 53", ""};

    static class Item {
        String name = "";
        String size = "";
        String date = "";
        String path = "";
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        txtRoot = findViewById(R.id.txtRoot);
        txtStatus = findViewById(R.id.txtStatus);
        txtBadge = findViewById(R.id.txtBadge);
        txtEmpty = findViewById(R.id.txtEmpty);
        spFilter = findViewById(R.id.spFilter);
        edFilter = findViewById(R.id.edFilter);
        edName = findViewById(R.id.edName);
        btnStart = findViewById(R.id.btnStart);
        btnStop = findViewById(R.id.btnStop);
        listFiles = findViewById(R.id.listFiles);

        ArrayAdapter<String> fa = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, filterLabels);
        fa.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spFilter.setAdapter(fa);
        spFilter.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                edFilter.setVisibility(position == 4 ? View.VISIBLE : View.GONE);
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });

        adapter = new ItemAdapter();
        listFiles.setAdapter(adapter);

        btnStart.setOnClickListener(v -> startCapture());
        btnStop.setOnClickListener(v -> stopCapture());
        findViewById(R.id.btnRefresh).setOnClickListener(v -> refreshFiles());

        listFiles.setOnItemClickListener((parent, view, position, id) -> share(items.get(position)));
        listFiles.setOnItemLongClickListener((parent, view, position, id) -> {
            confirmDelete(items.get(position));
            return true;
        });

        checkRoot();
        askNotification();
        refreshFiles();
        ui.post(tick);
    }

    // ---------- 权限 / root ----------

    private void askNotification() {
        if (Build.VERSION.SDK_INT >= 33
                && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 100);
        }
    }

    private void checkRoot() {
        txtRoot.setText("检测 root 权限…");
        new Thread(() -> {
            final boolean ok = Root.hasRoot();
            ui.post(() -> {
                txtRoot.setText(ok ? "ROOT ✓ 已连接本机 root 服务" : "root 服务不可用：" + Root.lastError);
                txtRoot.setTextColor(ContextCompat.getColor(this, ok ? R.color.accent : R.color.red));
                if (!ok && firstRootCheck) {
                    firstRootCheck = false;
                    new AlertDialog.Builder(this)
                            .setTitle("需要 root 权限")
                            .setMessage("系统抓包依赖 root 直接调用 tcpdump。\n\n本应用通过本机 root 服务执行 tcpdump，请确认「远程被控端」正在运行后重试。")
                            .setPositiveButton("重试", (d, w) -> checkRoot())
                            .setNegativeButton("知道了", null)
                            .show();
                }
            });
        }).start();
    }

    // ---------- 开始 / 停止 ----------

    private String currentFilter() {
        int i = spFilter.getSelectedItemPosition();
        if (i == 4) return edFilter.getText().toString().trim();
        if (i < 0 || i >= filterExprs.length) return "";
        return filterExprs[i];
    }

    private void startCapture() {
        btnStart.setEnabled(false);
        final String filter = currentFilter();
        final String name = edName.getText().toString().trim();

        new Thread(() -> {
            if (!Root.hasRoot()) {
                ui.post(() -> {
                    btnStart.setEnabled(true);
                    toast("没有 root 权限，无法抓包");
                    checkRoot();
                });
                return;
            }
            Intent i = new Intent(this, SniffService.class);
            i.setAction(SniffService.ACTION_START);
            i.putExtra(SniffService.EXTRA_NAME, name);
            i.putExtra(SniffService.EXTRA_FILTER, filter);
            ContextCompat.startForegroundService(this, i);

            try { Thread.sleep(1200); } catch (InterruptedException ignored) { }
            boolean ok = isRunning();
            ui.post(() -> {
                btnStart.setEnabled(!ok);
                btnStop.setEnabled(ok);
                running = ok;
                updateBadge(ok);
                if (ok) {
                    toast("开始抓包");
                    edName.setText("");
                } else {
                    toast("启动失败，请检查 root 授权");
                }
            });
        }).start();
    }

    private void stopCapture() {
        btnStop.setEnabled(false);
        new Thread(() -> {
            Intent i = new Intent(this, SniffService.class);
            i.setAction(SniffService.ACTION_STOP);
            startService(i);
            try { Thread.sleep(1500); } catch (InterruptedException ignored) { }
            ui.post(() -> {
                running = false;
                btnStart.setEnabled(true);
                btnStop.setEnabled(false);
                updateBadge(false);
                toast("已停止并保存");
                refreshFiles();
            });
        }).start();
    }

    private boolean isRunning() {
        Root.Result r = Root.run("if [ -f " + PID_FILE + " ] && kill -0 $(cat " + PID_FILE + ") 2>/dev/null; then echo YES; else echo NO; fi", 12);
        return r.out.contains("YES");
    }

    // ---------- 状态刷新 ----------

    private final Runnable tick = new Runnable() {
        @Override public void run() {
            new Thread(() -> {
                Root.Result r = Root.run(
                        "if [ -f " + PID_FILE + " ] && kill -0 $(cat " + PID_FILE + ") 2>/dev/null; then "
                                + "echo RUNNING; F=$(ls -t '" + DIR + "'/*.pcap 2>/dev/null | head -1); "
                                + "if [ -n \"$F\" ]; then echo \"$F\"; du -h \"$F\" | cut -f1; "
                                + "grep -o '[0-9]* packets captured' /data/adb/sniff.log 2>/dev/null | tail -1; "
                                + "else echo '-'; echo '-'; fi; "
                                + "else echo IDLE; fi", 12);
                final String out = r.out.trim();
                ui.post(() -> applyStatus(out));
            }).start();
            ui.postDelayed(this, 2000);
        }
    };

    private void applyStatus(String out) {
        boolean run = out.startsWith("RUNNING");
        if (run != running) {
            running = run;
            btnStart.setEnabled(!run);
            btnStop.setEnabled(run);
        }
        updateBadge(run);
        if (run) {
            String[] lines = out.split("\n");
            String file = lines.length > 1 ? lines[1] : "-";
            String size = lines.length > 2 ? lines[2] : "-";
            String packets = lines.length > 3 ? lines[3] : "";
            String shortName = file.contains("/") ? file.substring(file.lastIndexOf('/') + 1) : file;
            txtStatus.setText("正在抓包\n文件：" + shortName + "\n大小：" + size + (packets.isEmpty() ? "" : "\n" + packets));
        } else {
            txtStatus.setText("空闲（未在抓包）");
        }
    }

    private void updateBadge(boolean run) {
        txtBadge.setText(run ? "抓包中" : "空闲");
        txtBadge.setTextColor(ContextCompat.getColor(this, run ? R.color.red : R.color.sub));
    }

    // ---------- 文件列表 ----------

    private void refreshFiles() {
        new Thread(() -> {
            Root.Result r = Root.run("ls -lt '" + DIR + "'/*.pcap 2>/dev/null | head -30", 12);
            final List<Item> list = new ArrayList<>();
            for (String line : r.out.split("\n")) {
                line = line.trim();
                if (line.isEmpty() || !line.contains(".")) continue;
                String[] p = line.split("\\s+");
                if (p.length < 6) continue;
                Item it = new Item();
                it.size = p[3] != null ? p[3] : "-";
                it.path = p[p.length - 1];
                it.name = it.path.substring(it.path.lastIndexOf('/') + 1);
                it.date = p[4] + " " + p[5];
                list.add(it);
            }
            ui.post(() -> {
                items.clear();
                items.addAll(list);
                adapter.notifyDataSetChanged();
                txtEmpty.setVisibility(list.isEmpty() ? View.VISIBLE : View.GONE);
            });
        }).start();
    }

    private void share(Item it) {
        toast("正在准备文件…");
        new Thread(() -> {
            try {
                String tmp = getCacheDir().getAbsolutePath() + "/" + it.name;
                Root.Result r = Root.run("cp -f '" + it.path + "' '" + tmp + "'", 20);
                File f = new File(tmp);
                if (!f.exists() || f.length() == 0) {
                    // 尝试直接读（root 文件可能无权限）
                    r = Root.run("cat '" + it.path + "' > '" + tmp + "'", 30);
                }
                if (!f.exists() || f.length() == 0) {
                    ui.post(() -> toast("读取失败，请检查 root 授权"));
                    return;
                }
                Uri uri = FileProvider.getUriForFile(this, getPackageName() + ".fileprovider", f);
                ui.post(() -> {
                    Intent send = new Intent(Intent.ACTION_SEND);
                    send.setType("application/octet-stream");
                    send.putExtra(Intent.EXTRA_STREAM, uri);
                    send.putExtra(Intent.EXTRA_SUBJECT, it.name);
                    send.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                    startActivity(Intent.createChooser(send, "分享抓包文件"));
                });
            } catch (Exception e) {
                ui.post(() -> toast("分享失败：" + e.getMessage()));
            }
        }).start();
    }

    private void confirmDelete(Item it) {
        new AlertDialog.Builder(this)
                .setTitle("删除抓包文件")
                .setMessage(it.name)
                .setPositiveButton("删除", (d, w) -> {
                    new Thread(() -> {
                        Root.run("rm -f '" + it.path + "'", 15);
                        ui.post(this::refreshFiles);
                    }).start();
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshFiles();
    }

    // ---------- 列表适配器 ----------

    private class ItemAdapter extends BaseAdapter {
        @Override public int getCount() { return items.size(); }
        @Override public Object getItem(int position) { return items.get(position); }
        @Override public long getItemId(int position) { return position; }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null) {
                convertView = LayoutInflater.from(MainActivity.this).inflate(android.R.layout.simple_list_item_2, parent, false);
            }
            Item it = items.get(position);
            TextView t1 = convertView.findViewById(android.R.id.text1);
            TextView t2 = convertView.findViewById(android.R.id.text2);
            t1.setText(it.name);
            t1.setTextSize(13);
            t2.setText(it.size + " · " + it.date);
            t2.setTextSize(10);
            return convertView;
        }
    }
}
