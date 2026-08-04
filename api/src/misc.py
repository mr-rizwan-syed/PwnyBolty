"""
    Miscellaneous functions
"""
import os
import subprocess

# def run_cmd(command, shell=True, binary=False, env=None)-> tuple[str|bytes, str|bytes, int]:
def run_cmd(command, cwd=None)-> tuple[str|bytes, str|bytes, int]:
    """
        Run a command and returns the stdout, stderr, retcode
        obtained as a result of running the provided command
    """
    retcode = 0
    stdout = None
    stderr = None
    with subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        cwd=cwd) as proc:
        stdout, stderr = proc.communicate()
        retcode = proc.returncode

    return stdout.decode('utf-8'), stderr.decode('utf-8'), retcode

def run_cmd_check_file(cmd: str, file: str, logger, cwd=None):
    """Check if a file is created after running a cmd, if not, throw an exception"""
    stdout, stderr, retcode = run_cmd(cmd, cwd=cwd)
    
    # Verify launcher has been added 
    if not os.path.exists(file):
        logger.error(f"Failed to add Launcher.exe: `{cmd}` returned the following:")
        logger.error(f"Stdout:\n{stdout}")
        logger.error(f"Stderr:\n{stderr}")
        logger.error(f"Retcode:\n{retcode}")
        raise Exception(f"Command `{cmd}` failed to produce `{file}`")