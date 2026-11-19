package com.huskydg.magicv2ray;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Checks on app startup whether more than 3 days have elapsed since the last successful
 * geoip.dat / geosite.dat update. If so, downloads the latest release files asynchronously,
 * verifies their SHA-256 checksums, and atomically replaces the installed databases.
 */
final class GeoDataUpdater {

    private static final String TAG = "GeoDataUpdater";
    private static final String PREFS_NAME = "geo_data_updater";
    private static final String KEY_LAST_UPDATE_MS = "last_update_ms";

    /** Minimum interval between automatic updates: 3 days. */
    static final long UPDATE_INTERVAL_MS = TimeUnit.DAYS.toMillis(3);

    // Replace these URLs if you prefer v2fly upstream or a GitHub mirror.
    static final String GEOIP_URL =
            "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat";
    static final String GEOIP_SHA256_URL =
            "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat.sha256sum";
    static final String GEOSITE_URL =
            "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat";
    static final String GEOSITE_SHA256_URL =
            "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat.sha256sum";

    private static final int CONNECT_TIMEOUT_MS = 15_000;
    private static final int READ_TIMEOUT_MS = 60_000;
    private static final int MAX_REDIRECTS = 5;

    private static final AtomicBoolean RUNNING = new AtomicBoolean(false);

    private GeoDataUpdater() {
    }

    /**
     * Non-blocking entry point called after local startup setup completes.
     * Skips immediately if updated within the last 3 days or if an update is already running.
     */
    static void checkAndUpdateAsync(Context ctx) {
        final Context appCtx = ctx.getApplicationContext();
        SharedPreferences prefs = appCtx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        long lastUpdate = prefs.getLong(KEY_LAST_UPDATE_MS, 0L);
        long now = System.currentTimeMillis();
        if (lastUpdate > 0L && (now - lastUpdate) < UPDATE_INTERVAL_MS) {
            return;
        }
        if (!RUNNING.compareAndSet(false, true)) {
            return;
        }
        new Thread(() -> {
            try {
                boolean ok = performUpdate(appCtx);
                if (ok) {
                    prefs.edit().putLong(KEY_LAST_UPDATE_MS, System.currentTimeMillis()).apply();
                    Log.i(TAG, "geoip.dat & geosite.dat updated successfully");
                }
            } catch (Exception e) {
                Log.w(TAG, "geo database update failed, keeping existing files: " + e.getMessage());
            } finally {
                RUNNING.set(false);
            }
        }, "mv-geo-update").start();
    }

    private static boolean performUpdate(Context ctx) throws IOException {
        File stage = new File(ctx.getCacheDir(), "geo_update");
        deleteRecursive(stage);
        if (!stage.mkdirs() && !stage.isDirectory()) {
            throw new IOException("cannot create staging dir: " + stage);
        }
        try {
            File stagedGeoIp = new File(stage, "geoip.dat");
            File stagedGeoSite = new File(stage, "geosite.dat");

            String expectedIpHash = fetchExpectedSha256(GEOIP_SHA256_URL);
            String expectedSiteHash = fetchExpectedSha256(GEOSITE_SHA256_URL);

            boolean nonRoot = RunMode.isNonRoot(ctx);
            boolean needIp = !nonRoot || !expectedIpHash.equals(fileSha256OrNull(NonRootEnv.bin(ctx, "geoip.dat")));
            boolean needSite = !nonRoot || !expectedSiteHash.equals(fileSha256OrNull(NonRootEnv.bin(ctx, "geosite.dat")));

            if (!needIp && !needSite) {
                Log.i(TAG, "geo databases already match latest upstream SHA-256");
                return true;
            }

            if (needIp) {
                downloadAndVerify(GEOIP_URL, stagedGeoIp, expectedIpHash);
            }
            if (needSite) {
                downloadAndVerify(GEOSITE_URL, stagedGeoSite, expectedSiteHash);
            }

            if (nonRoot) {
                if (needIp) installNonRootFile(stagedGeoIp, NonRootEnv.bin(ctx, "geoip.dat"));
                if (needSite) installNonRootFile(stagedGeoSite, NonRootEnv.bin(ctx, "geosite.dat"));
                return true;
            } else {
                return installRootFiles(needIp ? stagedGeoIp : null, needSite ? stagedGeoSite : null);
            }
        } finally {
            deleteRecursive(stage);
        }
    }

    private static void installNonRootFile(File src, File dst) throws IOException {
        File tmp = new File(dst.getPath() + ".new");
        try (InputStream in = new FileInputStream(src); FileOutputStream out = new FileOutputStream(tmp)) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
        }
        if (!tmp.renameTo(dst)) {
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
            throw new IOException("cannot atomically replace " + dst);
        }
    }

    private static boolean installRootFiles(File stagedGeoIp, File stagedGeoSite) {
        if (stagedGeoIp == null && stagedGeoSite == null) {
            return true;
        }
        StringBuilder script = new StringBuilder();
        script.append("MOD=").append(RootShell.sq(ModuleInstaller.MODDIR)).append("\n");
        script.append("umask 022\n");
        script.append("put_geo() {\n");
        script.append("  cp \"$1\" \"$MOD/bin/$2.new\" || return 1\n");
        script.append("  chmod 0644 \"$MOD/bin/$2.new\" && chown 0:0 \"$MOD/bin/$2.new\" || return 1\n");
        script.append("  chcon u:object_r:system_file:s0 \"$MOD/bin/$2.new\" 2>/dev/null\n");
        script.append("  mv -f \"$MOD/bin/$2.new\" \"$MOD/bin/$2\"\n");
        script.append("}\n");
        if (stagedGeoIp != null) {
            script.append("put_geo ").append(RootShell.sq(stagedGeoIp.getAbsolutePath()))
                    .append(" geoip.dat || exit 1\n");
        }
        if (stagedGeoSite != null) {
            script.append("put_geo ").append(RootShell.sq(stagedGeoSite.getAbsolutePath()))
                    .append(" geosite.dat || exit 1\n");
        }
        script.append("exit 0\n");

        RootShell.Result r = RootShell.run(script.toString(), 60_000);
        if (!r.ok()) {
            Log.w(TAG, "root install of geo files failed: " + r.err.trim());
            return false;
        }
        // Reload root daemon so Xray picks up the updated .dat files immediately.
        ModuleInstaller.restartService();
        return true;
    }

    private static String fetchExpectedSha256(String shaUrl) throws IOException {
        HttpURLConnection conn = openWithRedirects(shaUrl);
        try (InputStream in = conn.getInputStream()) {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                bo.write(buf, 0, n);
            }
            String text = bo.toString(StandardCharsets.UTF_8.name()).trim();
            String token = text.split("\\s+")[0].toLowerCase(Locale.US);
            if (!token.matches("[0-9a-f]{64}")) {
                throw new IOException("invalid sha256sum from " + shaUrl + ": " + text);
            }
            return token;
        } finally {
            conn.disconnect();
        }
    }

    private static void downloadAndVerify(String fileUrl, File dst, String expectedSha256) throws IOException {
        HttpURLConnection conn = openWithRedirects(fileUrl);
        try (InputStream in = conn.getInputStream(); FileOutputStream out = new FileOutputStream(dst)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[64 * 1024];
            int n;
            long total = 0L;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                md.update(buf, 0, n);
                total += n;
            }
            if (total <= 0L) {
                throw new IOException("downloaded empty file from " + fileUrl);
            }
            String actual = toHex(md.digest());
            if (!expectedSha256.equals(actual)) {
                throw new IOException("SHA-256 mismatch for " + dst.getName()
                        + ": expected=" + expectedSha256 + " actual=" + actual);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 unavailable", e);
        } finally {
            conn.disconnect();
        }
    }

    private static HttpURLConnection openWithRedirects(String urlStr) throws IOException {
        String current = urlStr;
        for (int i = 0; i <= MAX_REDIRECTS; i++) {
            URL url = new URL(current);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestProperty("User-Agent", "Magic_V2Ray-GeoDataUpdater");
            int code = conn.getResponseCode();
            if (code == HttpURLConnection.HTTP_MOVED_PERM
                    || code == HttpURLConnection.HTTP_MOVED_TEMP
                    || code == HttpURLConnection.HTTP_SEE_OTHER
                    || code == 307
                    || code == 308) {
                String loc = conn.getHeaderField("Location");
                conn.disconnect();
                if (loc == null || loc.isEmpty()) {
                    throw new IOException("redirect without Location from " + current);
                }
                current = new URL(url, loc).toString();
                continue;
            }
            if (code != HttpURLConnection.HTTP_OK) {
                conn.disconnect();
                throw new IOException("HTTP " + code + " for " + current);
            }
            return conn;
        }
        throw new IOException("too many redirects for " + urlStr);
    }

    private static String fileSha256OrNull(File f) {
        if (!f.isFile() || f.length() <= 0L) return null;
        try (InputStream in = new FileInputStream(f)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
            return toHex(md.digest());
        } catch (IOException | NoSuchAlgorithmException e) {
            return null;
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private static void deleteRecursive(File f) {
        if (f == null || !f.exists()) return;
        File[] children = f.listFiles();
        if (children != null) {
            for (File c : children) deleteRecursive(c);
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
    }
}
