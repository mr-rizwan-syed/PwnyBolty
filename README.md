# PwnyBolty

**PwnyBolty** is a web-based payload factory for authorized red team engagements. It generates ready-to-deploy [ClickOnce](https://learn.microsoft.com/en-us/visualstudio/deployment/clickonce-security-and-deployment) packages that sideload a custom DLL into a Microsoft-signed binary via AppDomainManager Injection — no user-writable system paths or admin rights required.

Two build modes are supported:

| Mode | What it does |
|:-----|:-------------|
| **CFCO** | Executes shellcode, drops files, or runs OS commands on the target |
| **Bolthole** | Establishes a persistent reverse SSH tunnel back to your C2 server |

> **For authorized penetration testing engagements only.**

---

## Features

- **Shellcode execution** via a stripped-down DInvoke, redirected through `LdrCallEnclave` with an 8-minute startup delay to aid evasion
- **File drop** and **OS command execution** — both support runtime environment variable expansion
- **Payload inflation** — bloat the DLL's `.text` section (up to 10 MB, compiler-limited) or embed a resource file to push past EDR size-scan thresholds (up to 500 MB total)
- **Four sideload targets** — `tzsync`, `PerfWatson2`, `ServiceHub.Host.netfx.x64`, `powershell_ise`; all Microsoft-signed
- **Bolthole mode** — per-build operator keypairs, unique boltd host keys, auto-generated phishing page and C2 setup script

---

## How It Works

For architecture diagrams, build flow sequences, and payload encryption details, see the **[Technical Wiki](WIKI.md)**.

---

## Deployment

```bash
git clone https://github.com/mr-rizwan-syed/PwnyBolty
cd PwnyBolty
sudo docker compose up --build -d
```

The UI is available at `http://127.0.0.1:8080`.

| Path | Purpose |
|:-----|:--------|
| `./build/` | Generated payload zips, logs, operator keys |
| `./data/` | Persisted C2 config and global outbound keypair |
| `./logs/` | Caddy and API logs |

**Environment variables:**

| Variable | Default | Description |
|:---------|:--------|:------------|
| `DATA_CS_SIZE_IN_MB` | `10` | Max MB to inflate via `.text` section (compiler OOMs above this) |
| `BOLTHOLE_DATA_DIR` | `/app/data` | Persistent store for C2 config and keypair |

---

## Notes

- Shellcode execution uses a stripped-down [DInvoke](https://github.com/rasta-mouse/DInvoke/) via `LdrCallEnclave`. Execution is intentionally delayed by 8 minutes (four 2-minute pauses) to help with time-based detections.
- Inflation uses two layered methods: `.text` section bloat via `Data.cs` (capped at `DATA_CS_SIZE_IN_MB` to avoid compiler OOM), and an embedded `training.data` resource for anything beyond that cap.
- Bolthole builds generate unique ECDSA operator keypairs and RSA-2048 boltd host keys per build, preventing cross-target fingerprint correlation.

---

## References

### ClickForClickOnce
- Original project: [whokilleddb/clickforclickonce](https://github.com/whokilleddb/clickforclickonce)
- Talk: [WWHF Deadwood 2025 — Toolshed](https://wildwesthackinfest.com/wild-west-hackin-fest-deadwood-2025/)
- [Exploring ClickOnce and .NET Hijacking for SSH Initial Access — Steve Borosh](https://www.youtube.com/watch?v=Zid7tB0Iyss)
- [rasta-mouse/DInvoke](https://github.com/rasta-mouse/DInvoke/)

### Bolthole
- Original project: [rvrsh3ll/Bolthole](https://github.com/rvrsh3ll/Bolthole)
