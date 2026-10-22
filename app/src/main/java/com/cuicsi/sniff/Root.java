package com.cuicsi.sniff;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;

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

    public static Result run(String cmd, int timeoutSec) {
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
}
