package com.cuicsi.sniff;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;
import android.util.Log;

/** 通过 su 执行 root 命令 */
public class Root {

    public static class Result {
        public int code = -1;
        public String out = "";
        public boolean timeout = false;
    }

    public static Result run(String cmd) {
        return run(cmd, 20);
    }

    public static volatile String lastError = "";

    /** 本机 rc-agent 的令牌（它已以 root 运行，App 不必再申请 Magisk 授权） */
    private static final String AGENT = "http://127.0.0.1:8787/api/exec";
    private static final String TOKEN = "dc37f94344820df49639306cf9eae76c99e195d3a417ad36";

    public static Result run(String cmd, int timeoutSec) {
        Result r = runViaAgent(cmd, timeoutSec);
        if (r.code == 0 && !r.out.startsWith("执行失败")) return r;
        return runViaSu(cmd, timeoutSec);
    }

    /** 通过本机 root 代理执行（无需 Magisk 授权弹窗） */
    public static Result runViaAgent(String cmd, int timeoutSec) {
        Result r = new Result();
        java.net.HttpURLConnection c = null;
        try {
            java.net.URL url = new java.net.URL(AGENT);
            c = (java.net.HttpURLConnection) url.openConnection(java.net.Proxy.NO_PROXY);
            c.setRequestMethod("POST");
            c.setDoOutput(true);
            c.setConnectTimeout(4000);
            c.setReadTimeout(Math.max(5000, timeoutSec * 1000));
            c.setRequestProperty("Content-Type", "application/json");
            c.setRequestProperty("X-RC-Token", TOKEN);
            String body = "{\"cmd\":" + jsonStr(cmd) + ",\"timeout_ms\":" + (timeoutSec * 1000) + "}";
            java.io.OutputStream os = c.getOutputStream();
            os.write(body.getBytes("UTF-8"));
            os.close();
            int code = c.getResponseCode();
            java.io.InputStream is = code >= 400 ? c.getErrorStream() : c.getInputStream();
            java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(is, "UTF-8"));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append('\n');
            br.close();
            String resp = sb.toString();
            r.out = extract(resp, "output");
            r.code = 0;
        } catch (Exception e) {
            lastError = e.getClass().getSimpleName() + ": " + e.getMessage();
            Log.e("SniffRoot", "agent exec failed", e);
            r.out = "执行失败：" + lastError;
            r.code = -1;
        } finally {
            if (c != null) c.disconnect();
        }
        return r;
    }

    private static String jsonStr(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (char ch : s.toCharArray()) {
            switch (ch) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (ch < 0x20) sb.append(String.format("\\u%04x", (int) ch));
                    else sb.append(ch);
            }
        }
        return sb.append("\"").toString();
    }

    /** 从 {"data":{"exit":0,"output":"..."}} 里取 output（简易解转义） */
    private static String extract(String json, String key) {
        String k = "\"" + key + "\":\"";
        int i = json.indexOf(k);
        if (i < 0) return "";
        i += k.length();
        StringBuilder sb = new StringBuilder();
        while (i < json.length()) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) {
                char n = json.charAt(i + 1);
                if (n == 'n') sb.append('\n');
                else if (n == 't') sb.append('\t');
                else if (n == 'r') sb.append('\r');
                else sb.append(n);
                i += 2;
                continue;
            }
            if (c == '"') break;
            sb.append(c);
            i++;
        }
        return sb.toString();
    }

    public static Result runViaSu(String cmd, int timeoutSec) {
        Result r = new Result();
        Process p = null;
        try {
            p = new ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start();
            // 关闭 stdin，避免某些 su 实现等待输入
            try {
                OutputStream os = p.getOutputStream();
                os.write('\n');
                os.flush();
                os.close();
            } catch (Exception ignored) {}

            StringBuilder sb = new StringBuilder();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            long deadline = System.currentTimeMillis() + timeoutSec * 1000L;
            while (System.currentTimeMillis() < deadline) {
                if (br.ready()) {
                    line = br.readLine();
                    if (line == null) break;
                    sb.append(line).append('\n');
                } else if (!p.isAlive()) {
                    while ((line = br.readLine()) != null) sb.append(line).append('\n');
                    break;
                } else {
                    Thread.sleep(40);
                }
            }
            if (p.isAlive()) {
                r.timeout = true;
                p.destroyForcibly();
            }
            p.waitFor(2, TimeUnit.SECONDS);
            r.code = p.exitValue();
            r.out = sb.toString();
        } catch (Exception e) {
            r.out = "执行失败：" + e.getMessage();
        } finally {
            if (p != null) p.destroy();
        }
        return r;
    }

    public static boolean hasRoot() {
        Result r = run("id", 12);
        return r.out.contains("uid=0");
    }

    /** 本机 root 代理是否可用 */
    public static boolean hasAgent() {
        Result r = runViaAgent("id", 10);
        return r.code == 0 && r.out.contains("uid=0");
    }
}
