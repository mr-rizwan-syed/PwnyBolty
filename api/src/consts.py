"""
    This file contains all the constants used by the program
"""
import os
import logging

BUILD_DIR = "/app/static/build/"
SRC_TEMPLATE_DIR = "/templates/src"
BIN_TEMPLATE_DIR = "/templates/bin"
SIDELOAD_OPTIONS = [
    "tzsync",
    "systemhost",
    "perfwatson2",
    "powershell"
]

BUILD_CMD = "nuget install Newtonsoft.Json -Version 13.0.3 && msbuild /property:Configuration=Release /property:Platform=x64 /restore"

BOLTHOLE_SRC_TEMPLATE_DIR = "/templates/bolthole/src"
BOLTHOLE_BIN_TEMPLATE_DIR = "/templates/bolthole/bin/BoltFiles"
BOLTHOLE_BUILD_CMD = "msbuild /property:Configuration=Release /property:Platform=x64 /restore"
BOLTHOLE_SIDELOAD_OPTIONS = SIDELOAD_OPTIONS
DATA_CS_SIZE_IN_MB =  os.getenv("DATA_CS_SIZE_IN_MB") if os.getenv("DATA_CS_SIZE_IN_MB") else 10
INFLATE_SIZE = 50 * 1024 * 1024; # Inflate file size 

class LoggingConsts:
    """Class which contains all the different consts related to logging"""
    datefmt = "%Y-%m-%d %H:%M:%S" 

    c_format = "%(asctime)s.%(msecs)03d - %(levelname)s - %(name)s - %(message)s"
    c_formatter = logging.Formatter(c_format, datefmt=datefmt)
    
    f_format = "[%(asctime)s.%(msecs)03d] %(levelname)s [%(name)s] - %(message)s"
    f_formatter = logging.Formatter(f_format, datefmt=datefmt)

    g_logfile = "/logs/cfco.log"    
    l_logfile = "build.log"

    name = "cfco-api"

class Assembly:
    def __init__(self, name, sig, version):
        self.name = name 
        self.exe = f"{name}.exe"
        self.path = os.path.join(BIN_TEMPLATE_DIR, f"{self.exe}.deploy")
        self.key = sig
        self.version = version
        self.size = os.stat(self.path).st_size

# Get the public key using sn -T path/to/assembly.exe

POWERSHELL =    Assembly("powershell_ise",            "31bf3856ad364e35", "3.0.0.0")
TZSYNC =        Assembly("tzsync",                    "31bf3856ad364e35", "10.0.0.0" )
SVCHUB =        Assembly("ServiceHub.Host.netfx.x64", "b03f5f7f11d50a3a", "4.0.0.0"  )
PERFWATSON =    Assembly("PerfWatson2",               "b03f5f7f11d50a3a", "17.0.0.0" )
