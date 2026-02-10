#!/usr/bin/env -S uv run python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 rbaxim
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for details
"""
Modular Protocol Server
"""
# Python preinstalls
from __future__ import annotations
import subprocess
import sys
import importlib
import shlex
import os
import asyncio
import secrets
import logging
import re
import argparse
import time
import hashlib
import json
from pathlib import Path
import importlib.util
from typing import Literal, cast, BinaryIO, TextIO, Callable, TYPE_CHECKING, Optional, Union, Any, Tuple
import warnings
import signal
import shutil
import base64

def is_frozen():
    return getattr(sys, 'frozen', False) or bool(getattr(sys, '_MEIPASS', []))

def is_uv_available() -> bool:
    return shutil.which("uv") is not None

def get_certs():
    cert_dir = moppy_dir("certs")
    ssl_cert, ssl_key = None, None
    
    if any(cert_dir.glob("*.key")):
        cert_files = list(cert_dir.glob("*.pem"))
        key_files = list(cert_dir.glob("*.key"))

        if cert_files and key_files:
            # We take the first match found
            ssl_cert = str(cert_files[0].absolute())
            ssl_key = str(key_files[0].absolute())
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Found KEY and CERTIFICATE")
            return ssl_cert, ssl_key
        else:
            print(f"{Fore.YELLOW}WARNING{Fore.RESET}:  .pem or .key file missing in /moppy/certs")
        
        
    
    for file in cert_dir.glob("*.pem"):
        content = file.read_text()
        if "PRIVATE KEY" in content:
            ssl_key = str(file.absolute())
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Found KEY")
        elif "CERTIFICATE" in content:
            ssl_cert = str(file.absolute())
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Found CERTIFICATE")
        
    if not ssl_cert or not ssl_key:
        print(f"{Fore.YELLOW}WARNING{Fore.RESET}:  .pem or .key file missing in /moppy/certs")
    return ssl_cert, ssl_key

def is_docker() -> bool:
    if os.environ.get("AM_I_IN_A_DOCKER_CONTAINER", "").lower() == "true":
        return True

    if Path("/.dockerenv").exists():
        return True

    try:
        with open("/proc/1/cgroup", "rt", errors="ignore") as f:
            return any("docker" in line or "containerd" in line for line in f)
    except FileNotFoundError:
        return False

def moppy_path() -> Tuple[Literal[True], Path]:
    if Path("./moppy").exists():
        os.environ["MOPPY_PATH"] = str(Path("./moppy").absolute())
        return True, Path("./moppy").resolve(strict=False)
    else:
        moppy_path = os.environ.get("MOPPY_PATH", None)
        if moppy_path is None:
            print("[ERROR] MOPPY_PATH environment variable not set. Either move to the parent directory of moppy or set the variable to the path of moppy.")
            sys.exit(1)
        
        if Path(moppy_path).exists() and Path(moppy_path).is_dir():
            return True, Path(moppy_path).resolve(strict=False)
        elif Path(moppy_path).exists() and Path(moppy_path).is_file():
            print(f"[ERROR] MOPPY_PATH environment variable points to a file: {moppy_path}")
            sys.exit(1)
        else:
            print(f"[ERROR] MOPPY_PATH environment variable points to an invalid path: {moppy_path}")
            sys.exit(1)

MOPPY: Path = cast(Path, moppy_path()[1])

def moppy_dir(child: Path | str) -> Path:
    return MOPPY / child
    
    
uv = is_uv_available()

if __name__ == "__main__":
    print("[INFO] Python version: " + sys.version)
    print("[INFO] Is frozen: " + str(is_frozen()))
    print("[INFO] Is uv available: " + str(uv))
    print("[INFO] Is docker: " + str(is_docker()))
    print("[INFO] Found Moppy: " + str(moppy_path()[0]))
    
    

def module_exists(name: str) -> bool:
    return importlib.util.find_spec(name) is not None

def missing_deps(deps: list[str]) -> list[str]:
    installed = [d for d in deps if module_exists(d)]
    missing = [d for d in deps if d.lower() not in installed]
    for m in missing:
        print(f"[INFO] Missing dependency: {m}")
    return missing

def install_package(package_name: str):
        """Install a package using pip"""
        print(f"[INFO] Installing {package_name}...")
        if uv:
            base_cmd = ["uv", "pip", "install", package_name, "--quiet"]
        else:
            base_cmd = [sys.executable, "-m", "pip", "install", package_name, "--quiet"]
        
        try:
            subprocess.check_call(base_cmd)
        except subprocess.CalledProcessError as e:
            if sys.platform != "win32":
                print(f"[INFO] Failed to install {package_name}, retrying with --user...")
                user_cmd = base_cmd + ["--user"]
                try:
                    subprocess.check_call(user_cmd)
                except subprocess.CalledProcessError as e2:
                    print(f"[ERROR] Failed to install {package_name} even with --user: {e2}")
                    sys.exit(1)
            else:
                print(f"[ERROR] Failed to install {package_name}: {e}")
                sys.exit(1)
                
def pip_check_dependency(package_name: str):
    try:
        result = subprocess.run(
            ["uv", "pip", "check"] if uv else [sys.executable, "-m", "pip", "check"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError("uv is not available in this environment")

    output = result.stdout.strip()
    errors = result.stderr.strip()

    if not output and not errors:
        return {"ok": True, "issues": []}

    issues = []
    for line in output.splitlines():
        if package_name.lower() in line.lower():
            issues.append(line)

    return {
        "ok": len(issues) == 0,
        "issues": issues,
    }


if not is_frozen() and __name__ == "__main__":
    
    if not moppy_dir("pickles/pickle.jpeg").exists():
        print("[CRITICAL] pickle.jpeg is missing. attempting to boot without it. May fail with a extremely high chance")
        time.sleep(2)
        error_message = r"\xff\xfe\x00\x00C\x00\x00\x00O\x00\x00\x00M\x00\x00\x00P\x00\x00\x00L\x00\x00\x00E\x00\x00\x00T\x00\x00\x00E\x00\x00\x00\x00\x00\x00F\x00\x00\x00A\x00\x00\x00I\x00\x00\x00L\x00\x00\x00U\x00\x00\x00R\x00\x00\x00E\x00\x00\x00"
        print(f"[CRITICAL] FAILED TO BOOT. STATUS CODE: {error_message}")
        time.sleep(2)
        print("ok jokes over. time to boot")
        
    required_packages = [
        "fastapi",
        "hypercorn",
        "uvicorn",
        "psutil",
        "brotli_asgi",
        'aioquic',
        "slowapi",
        "colorama",
        "brotlicffi",
        "aiohttp",
        "base91",
        "aiofiles",
    ]
    
    if sys.platform != "win32":
        required_packages.append("uvloop")
    else:
        required_packages.append("pythonnet")

    # Check and install missing packages
    
    missing = missing_deps(required_packages)
    
    if missing:
        print("[INFO] Missing packages found. Installing...")
        for pkg in missing:
            install_package(pkg)
            check = pip_check_dependency(pkg)
            if not check["ok"]:
                print(f"[ERROR] pip check failed for {pkg}: {check['issues']}")
                sys.exit(1)
    else:
        print("[INFO] All required packages are installed! (Most likely warm boot)")
    print("[INFO] All MOP packages are installed! Checking for core plugin dependencies... (and you got color back. Horray!)")    
    
# Required installations
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect # pyright: ignore[reportMissingImports]  # noqa: E402
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse, StreamingResponse, Response, FileResponse # pyright: ignore[reportMissingImports]  # noqa: E402, F401
from fastapi.routing import APIRouter # pyright: ignore[reportMissingImports] # noqa: E402
from fastapi.openapi.utils import get_openapi # pyright: ignore[reportMissingImports] # noqa: E402
try:
    from hypercorn.config import Config as HyperConfig # pyright: ignore[reportMissingImports] # noqa: E402
    from hypercorn.asyncio import serve as hyper_serve # pyright: ignore[reportMissingImports] # noqa: E402
    HAS_HYPERCORN = True
except ImportError:
    HAS_HYPERCORN = False
try:
    import uvicorn # pyright: ignore[reportMissingImports] # noqa: E402
    HAS_UVICORN = True
except ImportError:
    HAS_UVICORN = False
from brotli_asgi import BrotliMiddleware # pyright: ignore[reportMissingImports] # noqa: E402
from slowapi import Limiter, _rate_limit_exceeded_handler # pyright: ignore[reportMissingImports]  # noqa: E402
from slowapi.util import get_remote_address # pyright: ignore[reportMissingImports]  # noqa: E402
from slowapi.errors import RateLimitExceeded  # pyright: ignore[reportMissingImports] # noqa: E402
from colorama import Fore, Style, Back, init as colorama_init # pyright: ignore[reportMissingModuleSource, reportMissingImports]  # noqa: E402, F401
import aiohttp # pyright: ignore[reportMissingImports] # noqa: E402
import psutil # pyright: ignore[reportMissingModuleSource, reportMissingImports] # noqa: E402
if TYPE_CHECKING:
    from psutil._common import addr # pyright: ignore[reportMissingModuleSource, reportMissingImports]  # noqa: E402
import moppy.utils as utils # pyright: ignore[reportMissingImports]  # noqa: E402
import base91 # pyright: ignore[reportMissingImports] # noqa: E402
import moppy.hints as hints # pyright: ignore[reportMissingImports]  # noqa: E402

colorama_init()

default_host: Literal["127.0.0.1", "0.0.0.0"] = "0.0.0.0" if is_docker() else "127.0.0.1"

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", type=int, default=8000, help="Sets the port for MOP to bind to")
parser.add_argument("--host", type=str, default=default_host, help="Sets the interface for MOP to bind to") # arg parser is weird and wont let me use -h
parser.add_argument("-c", "--cmd", type=str, default="echo Hello World!", required=True, help="The command for MOP to wrap with either pty or pipes")
parser.add_argument("-r", "--rate-limit", default=False, action="store_true", help="Enables rate limits for possible abusive endpoints (/mop/write, /mop/init, etc.)")
parser.add_argument("--cwd", default=os.getcwd(), type=str, help="Sets the CWD for the sessions to run in")
parser.add_argument("--ssl", default=False, action="store_true", help="Enables SSL")
parser.add_argument("-w", "--workers", default=1, type=int, help="Sets the amount of FastAPI workers to spawn")
parser.add_argument("--force-port", default=False, action="store_true", help="Disables interactive prompts when another process is bound to the port FastAPI wants to use and kills the process using the port without warning")
parser.add_argument("--no-pub-process", default=False, action="store_true", help="Prevents automatic creation of a public session")
parser.add_argument("--legacy", default=False, action="store_true", help="Uses uvicorn instead of Hypercorn")
args = parser.parse_args()

def steal_port(port):
    def get_pid_by_port(port):
        """
        Finds the PID of the process listening on the specified port.
        Returns the PID (int) or None if no process is found.
        """
        for conn in psutil.net_connections(kind='inet'):
            laddr = cast("addr", conn.laddr)
            if laddr.port == port and conn.status == psutil.CONN_LISTEN: # pyright: ignore[reportAttributeAccessIssue]
                return conn.pid
        return None

    used_port = get_pid_by_port(port)
    try:
        ps_port = psutil.Process(used_port)
        ps_PPID = psutil.Process(ps_port.ppid())
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        used_port = None
        return
    is_killed = False 
    
    if ps_port.pid == os.getpid():
        return
    
    if port and not args.force_port:
        print(f"{Fore.RED}ERROR{Fore.RESET}:    Port {args.port} is already in use by PID {used_port}.")
        print(f"{Fore.RED}ERROR{Fore.RESET}:    Process name: {ps_port.name()}")
        print(f"{Fore.RED}ERROR{Fore.RESET}:    Process status: {ps_port.status()}")
        print(f"{Fore.RED}ERROR{Fore.RESET}:    Process PPID: {ps_PPID.pid}")
        print(f"{Fore.RED}ERROR{Fore.RESET}:    Process PPID name: {ps_PPID.name()}")
        print(f"{Fore.RED}ERROR{Fore.RESET}:    Process PPID status: {ps_PPID.status()}")
        kill = input(f"{Fore.RED}ERROR{Fore.RESET}:    Do you want to kill the process? (y/n): ")
        if kill.lower() == "y":
            try:
                ps_port.terminate()
                print(f"{Fore.GREEN}INFO{Fore.RESET}:     Attempted to kill process. (SIGTERM)")
                ps_port.wait(timeout=3)
            except psutil.NoSuchProcess:
                print(f"{Fore.RED}ERROR{Fore.RESET}:    Failed to kill process.")
                sys.exit(1)
            except psutil.TimeoutExpired:
                print(f"{Fore.YELLOW}WARNING{Fore.RESET}:  Process did not terminate in time. Attempting to kill it with SIGKILL.")
                try:
                    ps_port.kill()
                except psutil.NoSuchProcess:
                    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Successfully killed process. (Process died after timeout)")
                    is_killed = True 
        is_not_killed = get_pid_by_port(args.port)
        if is_not_killed:
            print(f"{Fore.RED}ERROR{Fore.RESET}:    Failed to kill process.")
            sys.exit(1)
        elif not is_killed: # Confusing logic, i know
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Successfully killed process.")
    elif used_port and args.force_port:
        print(f"{Fore.YELLOW}WARNING{Fore.RESET}:  Port {args.port} is already in use by PID {used_port}. Forcing...")
        try:
            ps_port.terminate()
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Attempted to kill process. (SIGTERM)")
            ps_port.wait(timeout=3)
        except psutil.NoSuchProcess:
            print(f"{Fore.RED}ERROR{Fore.RESET}:    Failed to kill process.")
            sys.exit(1)
        except psutil.TimeoutExpired:
            print(f"{Fore.YELLOW}WARNING{Fore.RESET}:  Process did not terminate in time. Attempting to kill it with SIGKILL.")
            try:
                ps_port.kill()
                ps_port.wait(timeout=3)
            except psutil.NoSuchProcess:
                print(f"{Fore.GREEN}INFO{Fore.RESET}:     Successfully killed process. (Process died after timeout)")
                is_killed = True 
            except psutil.TimeoutExpired:
                print(f"{Fore.RED}ERROR{Fore.RESET}:    Failed to kill process.")
                sys.exit(1)
        is_not_killed = get_pid_by_port(args.port)
        if is_not_killed:
            print(f"{Fore.RED}ERROR{Fore.RESET}:    Failed to kill process.")
            sys.exit(1)
        elif not is_killed: # Confusing logic, i know
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Successfully killed process.")
            
pem_count = len(list(moppy_dir("certs").glob("*.pem")))

is_ssl_certs_exists = pem_count >= 1            

if args.ssl and not is_ssl_certs_exists:
    print(f"{Fore.RED}ERROR{Fore.RESET}:    .pem or .key file missing in /moppy/certs")
    prompt = input(f"{Fore.YELLOW}WARNING{Fore.RESET}:  Generate new SSL certificates? (y/n): ")
    if prompt.lower() != "y":
        print(f"{Fore.YELLOW}INFO{Fore.RESET}:     Exiting... Remove --ssl to disable SSL.")
        sys.exit(1)
    os.system(sys.executable + str(moppy_dir("ssl_certs.py")))            

if __name__ == "__main__":
    global core_plugins, non_core_plugins
    core_plugins: hints.Plugin_Manifest = {}
    non_core_plugins: hints.Plugin_Manifest  = {}  
    f: TextIO # pyright: ignore[reportRedeclaration]
    with open(moppy_dir("plugins/manifest.json"), "r") as f:
        try:
            manifest: hints.Plugin_Manifest = json.load(f)
        except json.JSONDecodeError:
            print(f"{Fore.RED}ERROR{Fore.RESET}:    Invalid plugin manifest!")
            sys.exit(1)
        except FileNotFoundError:
            print(f"{Fore.RED}ERROR{Fore.RESET}:    Plugin manifest not found!")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}ERROR{Fore.RESET}:    Failed to load plugin manifest: {e}")
            sys.exit(1)

    for name, plugin in manifest.items():
        if plugin.get("core", False):
            core_plugins[name] = plugin
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Found core plugin: {name}")
        else:
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Found non-core plugin: {name}")
            non_core_plugins[name] = plugin
            
    for name, plugin in core_plugins.items():
        missing = missing_deps(plugin.get("dependencies", []))
        if missing:
            for dep in missing:
                print(f"{Fore.RED}ERROR{Fore.RESET}:    Missing dependency: {dep}, Installing...")
                install_package(dep)
                check = pip_check_dependency(dep)
                if check["ok"]:
                    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Successfully installed dependency: {dep}")
                else:
                    print(f"{Fore.RED}ERROR{Fore.RESET}:    Failed to install dependency: {dep}, Issues: {check['issues']}")
                    sys.exit(1)
    
    safe_core_plugins = core_plugins.copy()
    safe_non_core_plugins = non_core_plugins.copy()
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Starting all core plugins")
    for name, plugin in safe_core_plugins.items():
        runtime = plugin["runtime"]
        plugin_location = plugin["location"].format(MOPPY=str(moppy_dir(plugin["location"].replace("{MOPPY}", ""))))
        runtime = runtime.format(location=plugin_location, port=plugin["port"] if plugin["port"] else "", host=args.host)
        mop_cwd = MOPPY
        
        steal_port(plugin["port"])
        
        cmd = shlex.split(runtime)
        if "ssl" in plugin["supports"] and args.ssl:
            cert, key = cast(tuple[str, str], get_certs())
            cmd.append("--ssl-certfile")
            cmd.append(str(Path(cert).absolute()))
            cmd.append("--ssl-keyfile")
            cmd.append(str(Path(key).absolute()))
        core_plugins[name]["handle"] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=mop_cwd) # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Starting core plugin:", name + f" at port {plugin['port']}" if plugin["port"] else "")
        core_plugin_handle: subprocess.Popen = cast(subprocess.Popen, core_plugins[name]["handle"])
        time.sleep(0.5)
        if core_plugin_handle.poll() is None:
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     {name} is running!")
        else:
            assert core_plugin_handle.stdout is not None, "Did you remove the pipe for stdout?"
            assert core_plugin_handle.stderr is not None, "Did you remove the pipe for stderr?"
            print(f"{Fore.RED}ERROR{Fore.RESET}:    {name} failed to start!")
            print(f"{Fore.RED}ERROR{Fore.RESET}:    Stdout: {core_plugin_handle.stdout.read().decode('utf-8', replace=True)}")
            print(f"{Fore.RED}ERROR{Fore.RESET}:    Stderr: {core_plugin_handle.stderr.read().decode('utf-8', replace=True)}")
            sys.exit(1)
    
    
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     All core plugins are running!")
    
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Starting all non-core plugins")
    for name, plugin in safe_non_core_plugins.items():
        runtime = plugin["runtime"]
        runtime = runtime.format(location=plugin["location"], port=plugin["port"] if plugin["port"] else "", host=args.host)
        mop_cwd = MOPPY
        
        steal_port(plugin["port"])
        
        cmd = shlex.split(runtime)
        if "ssl" in plugin["supports"] and args.ssl:
            cert, key = cast(tuple[str, str], get_certs())
            cmd.append("--ssl-certfile")
            cmd.append(str(Path(cert).absolute()))
            cmd.append("--ssl-keyfile")
            cmd.append(str(Path(key).absolute()))
        non_core_plugins[name]["handle"] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=mop_cwd) # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Starting plugin:", name + f" at port {plugin['port']}" if plugin["port"] else "")
        none_core_plugin_handle = cast(subprocess.Popen, core_plugins[name]["handle"])
        time.sleep(0.5)
        if none_core_plugin_handle.poll() is None:
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     {name} is running!")
        else:
            assert none_core_plugin_handle.stdout is not None, "Did you remove the pipe for stdout?"
            assert none_core_plugin_handle.stderr is not None, "Did you remove the pipe for stderr?"
            print(f"{Fore.RED}ERROR{Fore.RESET}:    {name} failed to start!")
            print(f"{Fore.RED}ERROR{Fore.RESET}:    Stdout: {none_core_plugin_handle.stdout.read().decode('utf-8', replace=True)}")
            print(f"{Fore.RED}ERROR{Fore.RESET}:    Stderr: {none_core_plugin_handle.stderr.read().decode('utf-8', replace=True)}")
            sys.exit(1)
            
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     All non-core plugins are running!")
    
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Running required scripts...")
    
    scripts = moppy_dir("scripts").glob("*.py")
    
    for script in scripts:
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Running script: {script}")
        handle = subprocess.Popen(["python", str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while handle.poll() is None:
            time.sleep(0.5)
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Ran script: {script}")

def is_uvicorn():
    try:
        parent_process = psutil.Process(os.getppid())
        if "uvicorn" in parent_process.name().lower():
            return True
        
        for arg in parent_process.cmdline():
            if "uvicorn" in arg.lower():
                return True
    except psutil.NoSuchProcess:
        pass # nosec
    return False

async def plugin_call(name, method="GET", content=None, path=""):
    if content is None:
        content = {}
    if name not in core_plugins.keys():
        raise FileNotFoundError(f"Plugin {name} not found")
    url = f"http://localhost:{core_plugins[name]['port']}/{path.lstrip('/') if path else ''}"
    async with aiohttp.ClientSession() as session:
        request_kwargs = {}

        if method.upper() == "GET":
            request_kwargs["params"] = content
        else:
            request_kwargs["json"] = content

        async with session.request(method, url, **request_kwargs) as response:
            response.raise_for_status()
            try:
                return await response.json()
            except aiohttp.ContentTypeError:
                return await response.text()


if sys.platform == "win32":
    if sys.version_info < (3, 14):
        # Deprecation warning here for 3.14+
        # TODO: Fix this before 3.16 where they remove it
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    else:
        print(f"{Fore.YELLOW}WARNING{Fore.RESET}:  You are using a python version that has deprecated the WindowsSelectorEventLoopPolicy. This may cause issues. Please use 3.13.2 or lower.")
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy()) # pyright: ignore[reportAttributeAccessIssue] Stub doesnt have it 
        

IS_CONPTY_AVAILABLE = False
if sys.platform == "win32":
    try:
        import ConPTYBridge.conpty as conpty
        IS_CONPTY_AVAILABLE = True
        conpty_dll_path = moppy_dir("ConPTYBridge/bin/Release/net8.0/ConPTYBridge.dll")
    except ImportError:
        print(f"{Fore.YELLOW}WARNING{Fore.RESET}:  You are not using the C# ConPTY wrapper for python. It is heavily recommended you install/build it for extra features")
        import winpty # pyright: ignore[reportMissingImports]
else:
    import fcntl
    import pty as unixpty
    
env = os.environ.copy()

env.update({
    "PYTHONUNBUFFERED": "1",
    "PYTHONIOENCODING": "utf-8",
    "TERM": "xterm",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "LANGUAGE": "C.UTF-8"
})

sessions: hints.Session_storage = {}

open("mop.log", "w").close()

logging.basicConfig(
    format="%(message)s",
    level=logging.DEBUG,
    handlers=[
        logging.FileHandler("mop.log"),
    ],
)

server_id = secrets.token_hex(16)
    
class StreamToLogger(hints.TextStream):
    """
    Fake file-like stream object that redirects writes to a logger instance.
    """
    def __init__(self, orignal, logger, level=logging.INFO):
        self.original = orignal
        self.logger = logger
        self.level = level
        self.buffer = ""

    def write(self, message: str) -> int: # pyright: ignore[reportIncompatibleMethodOverride]
        self.original.write(message)
        self.original.flush()
        
        message = message.rstrip()
        message = re.sub("(?:\x1B|\u001b)\\[[0-?]*[ -/]*[@-~]", "", message)
        if message:  # avoid logging empty lines
            self.logger.log(self.level, message)
        return len(message)

    def flush(self) -> None:
        pass  # Needed for file-like interface
    
    def isatty(self) -> bool:
        return True
    
logger = logging.getLogger("mop")

new_stdout: hints.TextStream = StreamToLogger(sys.stdout, logger, logging.INFO)
new_stderr: hints.TextStream = StreamToLogger(sys.stderr, logger, logging.ERROR)
sys.stdout = cast(TextIO, new_stdout)
sys.stderr = cast(TextIO, new_stderr)

command = shlex.split(args.cmd)
pub_key = secrets.token_hex(128)

global app

def create_app(command: list[str]):
    app = FastAPI(title="MOP", description="A stdio <-> HTTP(s) bridge.", version="1.0.0")
    app.state.command = command
    return app

app: FastAPI = create_app(command)

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    ws_path = "/mop/power/sock/{key}"
    
    openapi_schema["paths"][ws_path] = {
        "get": {
            "summary": "MOP WebSocket",
            "description": f"Bidirectional stream: Server sends stdout/stderr updates; Client sends stdin. **[AsyncAPI Portal](http{'s' if args.ssl else ''}://127.0.0.1:{args.port}/asyncDocs)**.",
            "tags": ["MOP Power Endpoints"],
            "parameters": [
                {
                    "name": "key",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                    "description": "Session key"
                }
            ],
            "responses": {
                "101": {
                    "description": "Switching Protocols",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/TerminalOutput"}
                        }
                    },
                    "headers": {
                        "Upgrade": {
                            "schema": {
                                "type": "string",
                                "example": "websocket"
                            }
                        },
                        "Connection": {
                            "schema": {
                                "type": "string",
                                "example": "Upgrade"
                            }
                        }
                    }
                }
            }
        }
    }

    # 3. Inject the Data Model for the Terminal Output
    if "schemas" not in openapi_schema["components"]:
        openapi_schema["components"]["schemas"] = {}
        
    openapi_schema["components"]["schemas"]["TerminalOutput"] = {
        "type": "object",
        "properties": {
            "stdout": {"type": "array", "items": {"type": "string"}},
            "stderr": {"type": "array", "items": {"type": "string"}}
        }
    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema

mop_router = APIRouter(tags=["MOP endpoints"])

app.openapi = custom_openapi # type: ignore[method-assign]

app.state.start_time = time.monotonic()
app.state.pepper =  b""

try:
    f_pepper: BinaryIO 
    with open(moppy_dir("pepper"), "rb") as f_pepper:
        f_pepper = cast(BinaryIO, f_pepper)
        app.state.pepper = bytes(base91.decode(f_pepper.read().split("🌶️".encode("utf-8"))[0]))
    
    if sys.platform != "win32":
        os.chmod(moppy_dir("pepper"), 0o600)
except FileNotFoundError:
    # Salt isnt found/generated yet
    app.state.pepper = secrets.token_bytes(32)
    f_pepper2: BinaryIO
    with open(moppy_dir("pepper"), "wb") as f_pepper2:
        f_pepper2 = cast(BinaryIO, f_pepper2)
        f_pepper2.write(base91.encode(app.state.pepper).encode("utf-8") + "🌶️".encode("utf-8"))
        
    if sys.platform != "win32":
        os.chmod(moppy_dir("pepper"), 0o600)
        
def big_hash(s) -> str:
    if s is None: 
        return ""
    b = s if isinstance(s, bytes) else str(s).encode("utf-8")
    return hashlib.sha512(app.state.pepper + b).hexdigest()

# everything and everybody says that this is bad and shouldnt be used. but then why is it working tho
def etag_response(func):
    async def wrapper(request: Request):
        # Call the original endpoint
        response = await func(request)

        # Only for JSONResponse or HTMLResponse
        if isinstance(response, (JSONResponse, HTMLResponse)):
            if isinstance(response.body, bytes):
                body_bytes = response.body
            elif isinstance(response.body, str):
                body_bytes = response.body.encode("utf-8")
            else:
                body_bytes = b""
            
            etag = hashlib.md5(body_bytes, usedforsecurity=False).hexdigest() # nosec
            # Check for If-None-Match header
            if request.headers.get("if-none-match") == etag:
                return JSONResponse(status_code=304, content=None)
            
            response.headers["ETag"] = etag
        
        return response
    return wrapper

app.add_middleware(BrotliMiddleware, minimum_size=256, quality=4, gzip_fallback=True)

limiter = Limiter(key_func=get_remote_address, enabled=bool(args.rate_limit), default_limits=[args.rate_limit] if args.rate_limit else [])
    
app.state.limiter = limiter

rate_limit_handler = cast(
    Callable[[Request, Exception], Response],
    _rate_limit_exceeded_handler
)

app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

def ratelimit(limit: str, doc_note = ""):
    def decorator(func):
        if limiter.enabled:
            func = limiter.limit(limit)(func)
        func.__doc__ = (func.__doc__ or "") + (f"{doc_note}" if doc_note else "")
        return func
    return decorator

@app.get("/asyncapi.yaml", include_in_schema=False)
@etag_response
async def serve_asyncapi_yaml(request: Request):
    accept_header = request.headers.get("accept", "")
    file_path = moppy_dir("asyncAPI.yaml")

    if "text/html" in accept_header:
        return FileResponse(
            file_path, 
            media_type="text/plain", 
            headers={"Content-Disposition": "inline"}
        )

    return FileResponse(
        file_path, 
        media_type="application/yaml",
        headers={"Content-Disposition": "inline"}
    )
    
@app.get("/asyncDocs", include_in_schema=False)
@etag_response
async def serve_asyncapi_docs(*args, **kwargs):
    return FileResponse(moppy_dir("asyncapi.html"), 200, media_type="text/html")

async def normalize_command(command: list[str]) -> list[str]:
    exe = command[0]

    p = Path(exe)

    # If already absolute, keep it
    if p.is_absolute():
        resolved = p
    else:
        # Resolve via PATH like the OS would
        found = shutil.which(exe)
        if not found:
            raise FileNotFoundError(f"Executable not found in PATH: {exe}")
        resolved = Path(found)

    # Canonicalize
    resolved = resolved.resolve()

    # Replace command[0] with absolute path
    command = command.copy()
    command[0] = str(resolved)
    
    return command


async def write(data: str, key: str, waivers: set[str | Any]):
    if key not in sessions:
        return {"status": "MOP transaction not started", "code": 1}, 428

    term: Terminal = sessions[key]["tty"]  # Terminal object
    
    if utils.Waiver.B64_STDIN in waivers:
        data = base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")

    # Optional: check if Unix subprocess is already terminated
    if sys.platform != "win32":
        if not term.proc:
            return {"status": "Subprocess already terminated", "code": 1}, 410
        elif term.proc.returncode is not None:
            return {"status": "Subprocess already terminated", "code": 1}, 410

    try:
        # Write to the terminal asynchronously
        if utils.Waiver.STREAM_STDIN in waivers:
            await term.write(data)
        else:
            if sys.platform == "win32":
                await term.write(data + "\r\n")
            else:
                await term.write(data + "\n")
    except (OSError, RuntimeError, BrokenPipeError) as e:
        return {"status": f"Failed to write to terminal: {e}", "code": 1}, 500
    except Exception as e:
        return {"status": f"Unexpected error: {e}", "code": 1}, 500

    return {"status": "Wrote data", "code": 0}, 200

async def read_stdout(key: str):
    # Just for websocket's sake
    data: utils.ByteLimitedLog = sessions[key]["buffers"].get("stdout", utils.ByteLimitedLog())
    new_data: list = data.buffer()
    if len(new_data) == 0:
        return ""
    
    return new_data[len(new_data) - 1]
    
class Terminal:
    def __init__(self, proc: Optional[asyncio.subprocess.Process] = None, master_fd: Optional[int]=None, pty_obj: Optional['winpty.PTY', "conpty.ConPTYInstance"]=None, use_pipes: bool = False): # type: ignore[name-defined, valid-type]
        self.use_pipes: bool = use_pipes
        
        self.proc: Optional[asyncio.subprocess.Process] # type: ignore[no-redef]
        
        if self.use_pipes:
            self.proc= cast(asyncio.subprocess.Process, proc) # type: ignore[no-redef]
        
        if sys.platform != "win32" and not self.use_pipes:
            self.master_fd: int = cast(int, master_fd)
            self.pty = None 
            self.proc = cast(asyncio.subprocess.Process, proc) # type: ignore[no-redef]
            self._read_buffer = bytearray()
            self._loop = asyncio.get_running_loop()
            self._closed = False
            self._prime_pty()

            self._loop.add_reader(self.master_fd, self._on_pty_readable)
        elif sys.platform == "win32" and not self.use_pipes:
            if IS_CONPTY_AVAILABLE:
                self.master_fd = None
                self.pty: conpty.ConPTYClient = cast(conpty.ConPTYClient, pty_obj) # pyright: ignore[reportRedeclaration]
                self.proc = None # pyright: ignore[reportAttributeAccessIssue] # type: ignore[no-redef, assignment]
            else:
                self.master_fd = None
                self.pty: winpty.PTY = cast(winpty.PTY, pty_obj)
                
                self.proc = None # pyright: ignore[reportAttributeAccessIssue] # type: ignore[no-redef, assignment]
        
    def _on_pty_readable(self):
        if sys.platform == "win32":
            return True # Handled differently on Windows.
        try:
            data = os.read(self.master_fd, 4096)
            if not data:
                # EOF
                print(f"{Fore.GREEN}INFO{Fore.RESET}:     Terminal closed due to EOF")
                self.close()
                return
            self._read_buffer.extend(data)
        except BlockingIOError:
            return
        except OSError as e:
            print(f"{Fore.GREEN}ERROR{Fore.RESET}:    Failed to read from terminal due to {str(e)}")
            self.close()
            
    def _prime_pty(self):
        while True:
            try:
                data = os.read(self.master_fd, 4096)
                if not data:
                    break  # EOF
                self._read_buffer.extend(data)
            except BlockingIOError:
                break
            except OSError as e:
                print(f"ERROR: Failed to read from terminal during prime: {e}")
                break


    async def read(self, n=1024, waivers: set[Any] = set()) -> dict[str, str]:
        loop = asyncio.get_running_loop()
        if self.use_pipes:
            proc = cast(asyncio.subprocess.Process, self.proc)
            stdout_obj = cast(asyncio.StreamReader, proc.stdout)
            stderr_obj = cast(asyncio.StreamReader, proc.stderr)
            stdout = await stdout_obj.read(n)
            stderr = await stderr_obj.read(n)
            return {"stdout": stdout.decode("utf-8"), "stderr": stderr.decode("utf-8")}
        if sys.platform == "win32":
            if IS_CONPTY_AVAILABLE:
                # ConPTY
                pty = cast(conpty.ConPTYClient, self.pty)
                loop = asyncio.get_running_loop()
                data = await loop.run_in_executor(None, lambda: pty.read(n))
                if utils.Waiver.RAW_ANSI in waivers:
                    return {"stdout": base64.b64encode(data).decode("utf-8", errors="replace"), "stderr": ""}
                else:
                    return {"stdout": data.decode("utf-8"), "stderr": ""}
            else:
                # winpty
                pty = cast(winpty.PTY, self.pty)
                loop = asyncio.get_running_loop()
                data = await loop.run_in_executor(None, lambda: pty.read())
                if utils.Waiver.RAW_ANSI in waivers:
                    return {"stdout": base64.b64encode(data).decode("utf-8", errors="replace"), "stderr": ""}
                else:
                    return {"stdout": data.decode("utf-8"), "stderr": ""}
        else:
            while not self._read_buffer and not self._closed:
                await asyncio.sleep(0.01)  # yield to loop

            if self._closed:
                return {"stdout": "", "stderr": ""}

            data = bytes(self._read_buffer[:n])
            del self._read_buffer[:n]
            if utils.Waiver.RAW_ANSI in waivers:
                return {"stdout": base64.b64encode(data).decode("utf-8"), "stderr": ""}
            else:
                return {"stdout": data.decode("utf-8", errors="replace"), "stderr": ""}
        return {"stdout": "", "stderr": ""}
        
    async def send_signal(self, sig: utils.Signal) -> None: # pyright: ignore[reportAttributeAccessIssue]
        loop = asyncio.get_running_loop()

        if self.proc is None:
            return
        
        if self.use_pipes:
            if sig == utils.Signal.INTERRUPT:
                self.proc.send_signal(signal.SIGINT)
            elif sig == utils.Signal.TERMINATE:
                self.proc.terminate()
            elif sig == utils.Signal.KILL:
                self.proc.kill()
            return

        # Ctrl+C is sent as a character, not a real signal
        if sig == utils.Signal.INTERRUPT:
            await self.write("\x03")

        # ---------- UNIX PTY ----------
        if sys.platform != "win32":
            UNIX_SIGNAL_MAP = {
                utils.Signal.TERMINATE: signal.SIGTERM,
                utils.Signal.KILL: signal.SIGKILL,
                utils.Signal.INTERRUPT: signal.SIGINT
            }
            
            unix_sig = UNIX_SIGNAL_MAP[sig]
            try:
                await loop.run_in_executor(
                    None, os.killpg, os.getpgid(self.proc.pid), unix_sig
                )
            except Exception:
                print(f"{Fore.RED}ERROR{Fore.RESET}:    Failed to send signal to {self.proc.pid}. Process unexepectedly died?")
            return
        else:
            pty = cast(Union["winpty.PTY", "conpty.ConPTYClient"], self.pty)
            if sig == utils.Signal.TERMINATE:
                os.kill(pty.pid, signal.CTRL_BREAK_EVENT) # pyright: ignore[reportArgumentType]
            elif sig == utils.Signal.KILL:
                os.kill(pty.pid, signal.SIGTERM) # pyright: ignore[reportArgumentType]
            elif sig == utils.Signal.INTERRUPT:
                os.kill(pty.pid, signal.CTRL_C_EVENT) # pyright: ignore[reportArgumentType] # Windows here
                
                
    async def _wait_writable(self, fd, timeout=5.0):
        """Properly wait for a file descriptor to become writable"""
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        
        def _on_writable():
            loop.remove_writer(fd)
            if not future.done():
                future.set_result(None)
        
        loop.add_writer(fd, _on_writable)
        try:
            await asyncio.wait_for(future, timeout)
        except asyncio.TimeoutError:
            loop.remove_writer(fd)
            raise TimeoutError(f"Write operation timed out after {timeout}s")
        finally:
            loop.remove_writer(fd)

        

    async def write(self, data: str, timeout=5.0) -> None:
        loop = asyncio.get_running_loop()
        
        if self.use_pipes:
            if self.proc is None:
                return
            stdin_obj = cast(asyncio.StreamWriter, self.proc.stdin)
            stdin_obj.write(data.encode())
            await stdin_obj.drain()
            return
            
        if sys.platform == "win32":
            # Windows implementation remains unchanged
            if self.pty is None:
                return
            if IS_CONPTY_AVAILABLE:
                pty = cast(conpty.ConPTYClient, self.pty)
                await loop.run_in_executor(None, pty.write, data.encode())
                return
            pty = cast(winpty.PTY, self.pty)
            await loop.run_in_executor(None, pty.write, data)
        else:
            if getattr(self, '_closed', False):
                return
            
            buf = memoryview(data.encode("utf-8"))
            start_time = asyncio.get_running_loop().time()
            MAX_WRITE_TIME = 2.0  # Critical timeout
            
            while buf:
                # Timeout protection - bail out if stuck
                if asyncio.get_running_loop().time() - start_time > MAX_WRITE_TIME:
                    logging.warning("Terminal write timed out - aborting")
                    break
                    
                try:
                    n = os.write(self.master_fd, buf)
                    buf = buf[n:]
                except BlockingIOError:
                    # Proper async wait with timeout
                    try:
                        await asyncio.wait_for(
                            self._wait_writable(self.master_fd),
                            timeout=0.5
                        )
                        print("BlockingIOError catched. Retrying write...")
                    except (asyncio.TimeoutError, asyncio.CancelledError):
                        print("Write Timeout exceeded")
                        break  # Give up and continue shutdown
                except (OSError, ValueError) as e:
                    logging.error(f"Terminal write error: {e}")
                    self.close()
                    break
            
    def close(self) -> None:
        self._closed = True
        
        if self.use_pipes:
            proc = cast(asyncio.subprocess.Process, self.proc)
            if proc:
                proc.terminate()
            return
            
        if sys.platform == "win32":
            if IS_CONPTY_AVAILABLE and hasattr(self, 'pty') and self.pty:
                pty = cast(conpty.ConPTYClient, self.pty)
                pty.close()
            elif hasattr(self, 'pty') and self.pty:
                pty = cast(winpty.PTY, self.pty)
                pty.close()
        else:
            if hasattr(self, '_loop') and hasattr(self, 'master_fd') and self.master_fd:
                try:
                    self._loop.remove_reader(self.master_fd)
                except Exception:
                    pass
                
                try:
                    self._loop.remove_writer(self.master_fd)
                except Exception:
                    pass
                    
            if hasattr(self, 'master_fd') and self.master_fd:
                try:
                    os.close(self.master_fd)
                except OSError:
                    pass
                    
            if self.proc:
                try:
                    self.proc.terminate()
                except Exception:
                    pass
            
    @property
    def is_pipe(self) -> bool:
        return self.use_pipes
    
    @property
    def pid(self) -> int:
        proc = cast(asyncio.subprocess.Process, self.proc)
        if self.is_pipe:
            return proc.pid
        if sys.platform == "win32":
            return self.pty.pid # pyright: ignore[reportReturnType]
        else:
            return proc.pid

async def spawn_tty(command: list[str], disable_echo=True) -> Terminal:
    new_cwd = Path(args.cwd).expanduser().resolve().absolute()
    if sys.platform == "win32":
        
        # Format environment variables as null-terminated string
        if IS_CONPTY_AVAILABLE:
            pty_obj = conpty.ConPTYClient(dll_path=str(conpty_dll_path.absolute())) # pyright: ignore[reportPossiblyUnboundVariable]
            command = await normalize_command(command) # Get absolute path for exe
            new_cmd = subprocess.list2cmdline(command)
            flags = 0x04
            if disable_echo:
                flags = 0
            pty_obj.start(str(new_cmd), 80, 24, flags, str(new_cwd), env)
            return Terminal(pty_obj=pty_obj)
        else:
            env_str = "\0".join(f"{k}={v}" for k, v in env.items()) + "\0\0"
            
            # Convert command list to single string
            cmd_str = " ".join(command)
            
            pty_obj = winpty.PTY( # pyright: ignore[reportPossiblyUnboundVariable]
                cols=80,
                rows=24,
            )
            
            pty_obj.spawn(
                appname=cmd_str,
                cmdline=cmd_str,
                cwd=str(new_cwd),
                env=env_str,
            )
                
                
            return Terminal(pty_obj=pty_obj)
    else:
        master_fd, slave_fd = unixpty.openpty()
        proc = await asyncio.create_subprocess_exec(
            *command,
            env=env,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            cwd=str(new_cwd),
            preexec_fn=lambda: utils.preexec(slave_fd, disable_echo)
        )
            
        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        
        os.close(slave_fd)
        return Terminal(proc=proc, master_fd=master_fd)
    
async def spawn_pipe(command: list[str]):
    new_cwd = Path(args.cwd).resolve()
    proc = await asyncio.create_subprocess_exec(
        *command,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        cwd=str(new_cwd),
    )
    return Terminal(proc=proc, use_pipes=True)

@mop_router.post("/mop/init", summary="Initialize Session", responses=hints.responses.MopInit())
@ratelimit("2/minute", "Ratelimit of 2 RPM")
async def init(options: hints.models.MopInit, request: Request):
    """
    Initalizes the PTY/Pipe.
    """
    command = app.state.command
    key = secrets.token_hex(64)
    hashed_key = big_hash(key)
        
    echo = options.echo
    attic = options.attic
    use_pipe = options.use_pipe
    
    if request.client is None:
        return JSONResponse({"status": "request.client is None", "comment": "Youre just as confused as i am. Blame Pylance", "code": 1}, status_code=500)
    
    if not use_pipe:
        process_handle = await spawn_tty(command, not echo)
    else:
        process_handle = await spawn_pipe(command)
    
    
    async def OUT_reader(default_key: str) -> None:
        buffers: hints.buffers_dict = sessions[default_key]["buffers"]
        tty: Terminal = sessions[default_key]["tty"]
        waivers = sessions[default_key].get("waivers", set())
        
        ANSI_CONTROL_RE = re.compile(
            r'\x1b'
            r'(?:'
                r'(?!\[[0-9;]*m)'        # keep SGR
                r'(?:\[[\?0-9;]*[A-Za-z])'  # CSI (non-SGR)
                r'|[@-Z\\-_]'            # 7-bit C1
            r')'
        )

        while True:
            try:
                # Unix: detect process exit if not using pipes
                if sys.platform != "win32" and not tty.is_pipe and tty.proc:
                    if tty.proc.returncode is not None:
                        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Process exited with code {tty.proc.returncode} for {default_key[:6]}")
                        buffers["stdout"].append(f"[PROCESS EXITED with code {tty.proc.returncode}]")
                        break

                data: dict[str, str] = await tty.read(waivers=cast(set[Any], waivers))
                if not data:
                    # just yield control, no busy-loop sleep
                    await asyncio.sleep(0)
                    continue

                stdout = data.get("stdout", "[ERROR reading stdout]")
                stderr = data.get("stderr", "[ERROR reading stderr]")

                if not tty.is_pipe and utils.Waiver.RAW_ANSI not in cast(set[Any], waivers):
                    stdout = ANSI_CONTROL_RE.sub('', stdout)
                    stderr = ANSI_CONTROL_RE.sub('', stderr)

                buffers["stdout"].append(stdout)
                buffers["stderr"].append(stderr)

            except Exception as e:
                buffers["stdout"].append(f"[ERROR reading stdout: {e}]")
                print(f"{Fore.GREEN}ERROR{Fore.RESET}:    {e}")
                break
            
    async def IN_pub_writer(pub_key: str):
        session: hints.PubSession = cast(hints.PubSession, sessions[pub_key])
        tty: Terminal = session["tty"]
        queue: asyncio.Queue[str] = session["queue"]

        while True:
            data = await queue.get()
            try:
                # Terminal.write should be async and non-blocking
                await tty.write(data)
            except Exception as e:
                logging.error(f"[ERROR writing stdin: {e}]")
            finally:
                queue.task_done()

    sessions[hashed_key] = cast(hints.PrivSession,{"tty": process_handle, "command": command, "buffers": {"stdout": utils.ByteLimitedLog(), "stderr": utils.ByteLimitedLog()}, "tags": [], "mode": "pty" if use_pipe else "pipe", "waivers": set()})
    sessions[hashed_key]["task_out"] = asyncio.create_task(OUT_reader(default_key=hashed_key))
    if pub_key not in sessions and not args.no_pub_process:
        pub_process_handle: Terminal = await spawn_tty(app.state.command, not echo)
        sessions[pub_key] = cast(hints.PubSession, {"tty": pub_process_handle, "command": command, "buffer": [], "queue": asyncio.Queue(), "tags": ["public"], "mode": "pty"})
        sessions[pub_key]["task_out"] = asyncio.create_task(OUT_reader(default_key=pub_key))
        cast(hints.PubSession, sessions[pub_key])["task_in"] = asyncio.create_task(IN_pub_writer(pub_key=pub_key))
    attic_out = ""
    if attic:
        try:
            attic_out = await utils.attic(hashed_key, process_handle.pid).get()
        except Exception as e:
            logging.error(f"[ERROR retrieving attic: {e}]")
            del sessions[hashed_key]
            if len(sessions) < 2:
                del sessions[pub_key]
            return JSONResponse({"status": "Error retrieving attic", "code": 1, "error": str(e)}, status_code=500)
    
    client = f"{request.client.host}:{request.client.port}"
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     {client} - Session {hashed_key[:6]} started")
    response = {"status": "Session started", "code": 0, "key": key, "public_key": pub_key if not args.no_pub_process else ""}
    if attic:
        attic = cast(str, attic)
        response["attic"] = attic_out
        response["key"] = attic
        sessions[hashed_key]["tty"].close()
        del sessions[hashed_key]
        sessions[attic] = cast(hints.PrivSession, {"tty": process_handle, "command": command, "buffers": {"stdout": [], "stderr": []}, "tags": ["attic"], "mode": "pty"})
        sessions[attic]["task_out"] = asyncio.create_task(OUT_reader(default_key=attic))
    return JSONResponse(response, status_code=200)

@mop_router.post("/mop/validate", summary="Validate key", responses=hints.responses.MopValidate())
@ratelimit("10/minute", "Ratelimit of 10 RPM")
async def validate(options: hints.models.MopValidate):
    """
    Validates your keys.
    """
    key: str = options.key
    if key == pub_key:
        return JSONResponse({"status": "Public key", "code": 0}, status_code=200)
    if big_hash(key) not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1}, status_code=404)
    return JSONResponse({"status": "Key exists", "code": 0}, status_code=200)

@mop_router.post("/mop/attic/tell", responses=hints.responses.MopAtticTell())
@ratelimit("5/minute", "Ratelimit of 5 RPM")
async def tell_attic(options: hints.models.MopAtticTell):
    """
    Tell Attic to tell your session's process some data.
    """
    key: str = options.key
    info = options.info
    hashed_key = big_hash(key)
    if key == pub_key:
        return JSONResponse({"status": "Cannot tell process data for public key", "code": 1}, status_code=403)
    if hashed_key not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1}, status_code=404)
    try:
        out = utils.attic(hashed_key, sessions[hashed_key]["tty"].pid).tell(info)
    except Exception as e:
        return JSONResponse({"status": f"Failed to tell process data due to {str(e)}"})
    
    return JSONResponse({"status": "Sucessfully got attic output","attic_response": out, "code": 0}, status_code=200)

@mop_router.post("/mop/cosmetics/get_tags", responses=hints.responses.MopCosmeticsGet_tags())
async def get_tags(options: hints.models.MopCosmeticsGet_tags):
    """
    Get tags for your session
    """
    key: str = big_hash(options.key)
    if key not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1}, status_code=404)
    
    return JSONResponse({"tags": sessions[key]["tags"], "code": 0}, status_code=200)

@mop_router.post("/mop/cosmetics/set_tags", responses=hints.responses.MopCosmeticsSet_tags())
async def set_tags(options: hints.models.MopCosmeticsSet_tags):
    """
    Set tags for your session
    """
    key: str = big_hash(options.key)
    if key not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1}, status_code=404)
    
    sessions[key]["tags"] = options.tags
    return JSONResponse({"status": "Tags updated", "code": 0}, status_code=200)

@mop_router.post("/mop/set_attic", responses=hints.responses.MopSet_attic())
async def persist_session(options: hints.models.MopSet_attic):
    """
    Sets the attic flag so your session will be marked as persistent.
    """
    key: str = options.key
    hashed_key: str = big_hash(key)
    if key == pub_key:
        return JSONResponse({"status": "Cannot set attic flag for public key", "code": 1}, status_code=403)
    
    if hashed_key not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1}, status_code=404)
    
    session_copy = cast(hints.PrivSession, sessions[hashed_key]).copy()
    
    session_copy["attic"] = True
    sessions[hashed_key] = session_copy
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Attic flag set for {hashed_key[:6]}")
    return JSONResponse({"status": "Attic flag set", "code": 0}, status_code=200)

@mop_router.post("/mop/power/stream/read", summary="SSE stdout", responses=hints.responses.MopPowerStreamRead(), tags=["MOP Power Endpoints"])
async def sse_read(options: hints.models.MopPowerStreamRead, request: Request):
    """
    SSE stdout stream
    """
    # 1. Auth Check (Crucial for Power endpoints)
    key: str = big_hash(options.key)
    if key not in sessions:
        return JSONResponse({"status": "Invalid Key"}, status_code=404)

    async def event_generator():
        while True:
            # 2. Check for disconnect (Stop wasting CPU if they leave)
            if await request.is_disconnected():
                break
            

            # 3. Pull from your existing stdout buffer
            # This is where your PTY data lives
            new_data = await read_stdout(key)

            if new_data:
                # SSE Format: "data: <content>\n\n"
                yield f"data: {new_data}\n\n"

            # 4. Small sleep to prevent CPU spinning
            await asyncio.sleep(0.1)

    return StreamingResponse(event_generator(), media_type="text/event-stream", status_code=200)

@app.websocket("/mop/power/sock/{key}")
async def power_sock(websocket: WebSocket, key: str):
    hashed_key = big_hash(key)
    if hashed_key not in sessions:
        await websocket.close(code=1008)
        return
    
    is_pub_key = False
    
    if key == pub_key:
        is_pub_key = True
    
    await websocket.accept()
    if websocket.client is None:
        await websocket.close(code=1011)
        return
    client = f"{websocket.client.host}:{websocket.client.port}"
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     {client} - Session {hashed_key[:6]} connected")
    
    try:
        async def send_to_client() -> None:
            sent_stdout_count = 0
            sent_stderr_count = 0
            
            while True:
                buffer_data = cast(hints.PrivSession, sessions[hashed_key])["buffers"]
                stdout_full = buffer_data["stdout"].buffer()
                stderr_full = buffer_data["stderr"].buffer()

                new_stdout = stdout_full[sent_stdout_count:]
                new_stderr = stderr_full[sent_stderr_count:]

                if new_stdout or new_stderr:
                    payload = {
                        "stdout": new_stdout, 
                        "stderr": new_stderr
                    }
                    await websocket.send_text(json.dumps(payload))
                    
                    sent_stdout_count = len(stdout_full)
                    sent_stderr_count = len(stderr_full)

                await asyncio.sleep(0.1)
                
        async def receive_from_client() -> None:
            last_msg_time = time.time()
            msg_count = 0
            while True:
                data = await websocket.receive_text()
                
                # Rate limiting / Backpressure
                current_time = time.time()
                if current_time - last_msg_time < 1.0:
                    msg_count += 1
                else:
                    msg_count = 0
                    last_msg_time = current_time
                    
                if msg_count > 50:
                    await websocket.close(code=1008)
                
                if is_pub_key:
                    # Use the global pub_key session queue
                    cast(hints.PubSession, sessions[pub_key])["queue"].put_nowait(data)
                else:
                    waivers = cast(hints.PrivSession, sessions[hashed_key])["waivers"]
                    await write(data, hashed_key, waivers)

        await asyncio.gather(send_to_client(), receive_from_client())

    except WebSocketDisconnect:
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     {client} - Session {hashed_key[:6]} disconnected")

@mop_router.post("/mop/signal", summary="Send signals", responses=hints.responses.MopSignal())
async def signalButRequest(options: hints.models.MopSignal):
    """
    Sends signals 
    
    Valid Signals:
    
    - INTERRUPT
    
    - TERMINATE
    
    - KILL
    """
    key: str = options.key
    signal = cast(Literal["INTERRUPT", "TERMINATE", "KILL"], options.signal.upper())
    signal_map = {
        "INTERRUPT": utils.Signal.INTERRUPT,
        "TERMINATE": utils.Signal.TERMINATE,
        "KILL": utils.Signal.KILL
    }
    if signal not in signal_map:
        return JSONResponse({"status": "Invalid signal", "code": 1}, 404)
        
    if key == pub_key:
        return JSONResponse({"status": "Cannot send any signal to public key", "code": 1}, 403)
            
    hashed_key: str = big_hash(key)
    if hashed_key not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1}, 404)
    
    try:
        if signal in ("INTERRUPT", "TERMINATE", "KILL"): # Future safe code
            await sessions[hashed_key]["tty"].send_signal(signal_map[signal])
            cast(asyncio.Task, sessions[hashed_key]["task_out"]).cancel()
            cast(Terminal, sessions[hashed_key]["tty"]).close()
        else:
            await sessions[hashed_key]["tty"].send_signal(signal_map[signal])
        del sessions[hashed_key]
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Sent signal {signal} to session {hashed_key[:6]}")
        if len(sessions) < 2:
            cast(hints.PubSession, sessions[pub_key])["task_out"].cancel()
            cast(hints.PubSession, sessions[pub_key])["queue"].put_nowait(None)
            cast(hints.PubSession, sessions[pub_key])["task_in"].cancel()
            cast(hints.PubSession, sessions[pub_key])["tty"].close()
            del sessions[pub_key]
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Killed public session {pub_key[:6]} due to no other sessions remaining")
        return JSONResponse({"status": "Signal sent", "code": 0})
    except Exception:
        return JSONResponse({"status": "Failed to send signal", "code": 1})
    
@mop_router.post("/mop/end", summary="End Session", responses=hints.responses.MopEnd())
async def end(options: hints.models.MopEnd, request: Request):
    """
    Ends the session
    """
    data = await request.json()
    key: str = options.key
    hashed_key: str = big_hash(key)
    failed_to_store: str = ""
    if hashed_key not in sessions and key != pub_key:
        return JSONResponse({"status": "Invalid key", "code": 1}, 404)

    term: Terminal = sessions[hashed_key]["tty"]  # Terminal object
    
    if request.client is None:
        return JSONResponse({"status": "Client not found", "comment": "youre just as confused as i am. blame pylance","code": 1}, status_code=500)

    try:
        # Cancel the readers first
        sessions[hashed_key]["task_out"].cancel()

    except Exception:
        pass

    # Kill/close the terminal subprocess
    if sys.platform == "win32" and not term.is_pipe:
        try:
            await term.send_signal(utils.Signal.KILL)
        except Exception:
            pass
    elif sys.platform != "win32" and not term.is_pipe:
        try:
            proc = cast(asyncio.subprocess.Process, term.proc)
            await term.send_signal(utils.Signal.TERMINATE)
            await proc.wait()
            os.close(term.master_fd)
        except Exception:
            pass
    elif term.is_pipe:
        try:
            if term.proc is None:
                return JSONResponse({"status": "Terminal not found", "code": 1}, status_code=500)
            await term.send_signal(utils.Signal.TERMINATE)
            await term.proc.wait()
        except Exception:
            pass

    # Remove from sessions
    if not sessions[hashed_key].get("attic", False):
        del sessions[hashed_key]
    else:
        # Send to attic
        try:
            await utils.attic(hashed_key, term.pid).set(data.get("pickle", {}))
            print(f"{Fore.GREEN}INFO{Fore.RESET}:    {request.client.host}:{request.client.port} - Key {hashed_key[:6]} stored in attic")
            await asyncio.sleep(0.5)
        except Exception as e:
            failed_to_store = str(e)
            print(f"{Fore.RED}ERROR{Fore.RESET}:    {request.client.host}:{request.client.port} - Key {hashed_key[:6]} failed to store in attic")
            
        del sessions[hashed_key]

    # Clean up public key session if no other sessions remain
    if len(sessions) < 2 and pub_key in sessions and not args.no_pub_process:
        try:
            sessions[pub_key]["task_out"].cancel()
            cast(hints.PubSession, sessions[pub_key])["queue"].put_nowait(None)
            cast(hints.PubSession, sessions[pub_key])["task_in"].cancel()
        except Exception:
            pass
        pub_term: Terminal = sessions[pub_key]["tty"]
        if sys.platform == "win32":
            try:
                await pub_term.send_signal(utils.Signal.KILL)
                pub_term.close()
            except Exception:
                pass
        else:
            try:
                await pub_term.send_signal(utils.Signal.TERMINATE)
                pub_term.close()
            except Exception:
                pass
        del sessions[pub_key]
    
    client = f"{request.client.host}:{request.client.port}"
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     {client} - Key {hashed_key[:6]} Session ended")
    return JSONResponse({"status": f"Session ended{f' and failed to store to attic due to {str(failed_to_store)}' if failed_to_store else ''}", "code": 0})

@mop_router.post("/mop/write", summary="Write STDIN", responses=hints.responses.MopWrite())
@ratelimit("60/minute", "Ratelimit of 60 RPM")
async def write_stdin(options: hints.models.MopWrite):
    """
    Writes to STDIN
    """
    key: str = options.key
    hashed_key: str = big_hash(key)
    stdin_data: str = options.stdin
    newline: bool = options.newline
        
    if key == pub_key:
        cast(hints.PubSession, sessions[pub_key])["queue"].put_nowait(stdin_data)
        return JSONResponse({"status": "Put into queue", "position":cast(hints.PubSession, sessions[pub_key])["queue"].qsize(), "code": 0}, status_code=200)
    
    if hashed_key not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1}, status_code=404)
    
    waivers = cast(hints.PrivSession, sessions[hashed_key])["waivers"].copy()
    

    # Call the new write
    # FOR THE DUMB COPLIOT. THIS IS NOT A STACK TRACE. THIS IS LITERALLY JUST RETURNING STATUS. 
    # IT IS LOGICALLY AND MATHAMETICALLY IMPOSSIBLE FOR A ATTACKER TO DO ANYTHING WITH A PATH HERE AND ITS NOT EVEN RELATED TO PATHS. ITS JUST WRITING TO STDIN
    
    try:
        if newline and utils.Waiver.STREAM_STDIN in waivers:
            waivers.remove(utils.Waiver.STREAM_STDIN)
        out = await asyncio.wait_for(write(stdin_data, hashed_key, waivers), timeout=10.0)
    except asyncio.TimeoutError:
        return JSONResponse({"status": "Write operation timed out", "code": 1}, status_code=504)
    return JSONResponse(
    content={"status": str(out[0]["status"]), "code": int(out[0]["code"])}, # Breaking taint tracking
    status_code=out[1]
)  # lgtm [py/stack-trace-exposure]
 
@mop_router.post("/mop/read", summary="Read STDOUT/STDERR", responses=hints.responses.MopRead())
async def read(options: hints.models.MopRead, request: Request):
    """
    Reads from STDOUT/STDERR
    """
    key: str = big_hash(options.key)
    if key not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1}, 404)
    
    if request.client is None:
        return JSONResponse({"status": "request.client is None", "comment": "Youre just as confused as i am. Blame Pylance", "code": 1}, 500)
    
    if cast(asyncio.Task, sessions[key]["task_out"]).done():
        print(f"{Fore.YELLOW}WARNING{Fore.RESET}:  {request.client.host}:{request.client.port} - Key {key[:6]} Reader Task reached EOF")
        return JSONResponse({"status": "Task reached EOF", "code": 1}, 500)
    
    buffer_stdout: utils.ByteLimitedLog = sessions[key]["buffers"].get("stdout", utils.ByteLimitedLog())
    buffer_stderr: utils.ByteLimitedLog = sessions[key]["buffers"].get("stderr", utils.ByteLimitedLog())
    stdout: list = buffer_stdout.buffer()
    stderr: list = buffer_stderr.buffer()
    
    out: dict[str, list[str]] = {"stdout": stdout, "stderr": stderr}
    return JSONResponse({"stdout": out["stdout"], "stderr": out.get("stderr", ""), "code": 0, "output_hash": hashlib.md5(cast(memoryview,json.dumps(out, sort_keys=True).encode("utf-8")), usedforsecurity=False).hexdigest()}, status_code=200) # nosec

@mop_router.post("/mop/waiver", summary="Set/Remove Waivers", responses=hints.responses.MopWaiver())
async def waiver(options: hints.models.MopWaiver):
    """
    Set waivers for extra explict features 
    
    Valid Waivers:
    
    | Waiver | Type | Description |
    | --- | --- | --- |
    | RAW_ANSI | Flag | Disables STDOUT/STDERR Non-SGR ansi filtering. Output in URL safe Base64 |
    | B64_STDIN | Flag | Allows you to send binary data via URL safe Base64 |
    | STREAM_STDIN | Flag | Removes the default OS-Specific line ending. Add ```{"newline": true}``` to your /mop/write calls to add a newline |
    """
    key: str = big_hash(options.key)
    remove: list[str] = options.remove
    waivers: dict[str, Any] = options.waivers
    if key not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1}, status_code=404)
    
    if options.key == pub_key:
        return JSONResponse({"status": "Cannot set waiver for public key", "code": 1}, status_code=403)
    
    if not waivers:
        return JSONResponse({"status": "No waivers set", "code": 0}, status_code=200) 
    
    for waiver, value in waivers.items():
        if waiver.lower() == "raw_ansi":
            cast(hints.PrivSession, sessions[key])["waivers"].add(utils.Waiver.RAW_ANSI)
        elif waiver.lower() == "b64_stdin":
            cast(hints.PrivSession, sessions[key])["waivers"].add(utils.Waiver.B64_STDIN)
        elif waiver.lower() == "stream_stdin":
            cast(hints.PrivSession, sessions[key])["waivers"].add(utils.Waiver.STREAM_STDIN)
        else:
            return JSONResponse({"status": f"Unknown waiver: {waiver}", "code": 1}, status_code=404)
            
    for waiver in remove:
        try:
            cast(hints.PrivSession, sessions[key])["waivers"].remove(waiver)
        except Exception:
            return JSONResponse({"status": "Unable to remove waiver"}, status_code=500)
            
    return JSONResponse({"status": "Waiver(s) set/removed", "code": 0}, status_code=200)

@mop_router.post("/mop/ping", summary="Ping Process", responses=hints.responses.MopPing())
async def ping(options: hints.models.MopPing):
    """
    Pings your session and checks if it is alive
    """
    key: str = big_hash(options.key)
    
    if key not in sessions:
        return JSONResponse({"status": "Session not found", "code": 1}, status_code=404)
    
    term = sessions[key]["tty"]
    
    # Check if process is alive
    if sys.platform == "win32":
        pty = cast(Union["conpty.ConPTYClient","winpty.pty"], term.pty)
        if IS_CONPTY_AVAILABLE:
            pty = cast(conpty.ConPTYClient, term.pty)
            is_alive = pty.is_alive()
        else:
            pty = cast(winpty.PTY, term.pty)
            is_alive = pty.is_alive()
    else:
        is_alive = cast(asyncio.subprocess.Process, term.proc).returncode is None
    
    if is_alive:
        return JSONResponse({"status": "Process is alive", "code": 0}, status_code=200)
    else:
        return JSONResponse({"status": "Process is terminated", "code": 1}, status_code=410)

@mop_router.get("/mop/process", summary="Ping Server Process", responses=hints.responses.MopProcess())
async def process():
    """
    Returns information on the server
    """
    if pub_key not in sessions:
        return JSONResponse(
            {
                "status": "No process is running.", 
                "server_id": server_id,
                "command": list(app.state.command),
                "uptime": f"{int(time.monotonic() - app.state.start_time)}",
                "version": "1.0.0",
                "code": 0
            }, status_code=428)
    data = {
        "command": list(app.state.command),
        "server_id": server_id,
        "sessions": len(sessions.keys()),
        "pub_key": pub_key,
        "pending_writes": cast(hints.PubSession, sessions[pub_key])["queue"].qsize(),
        "uptime": f"{int(time.monotonic() - app.state.start_time)}",
        "version": "1.0.0",
        "code": 0
    }
    return JSONResponse(data, status_code=200)

app.include_router(mop_router)

@app.get("/", responses=hints.responses.Root())
async def root(request: Request):
    if request.headers.get("Accept", "text/plain") == "application/json":
        return JSONResponse({"status": "use /mop/", "comment": "wrong url bud. its /mop","code": 0}, status_code=400)
    
    return PlainTextResponse("I think you may have gotten the wrong url buddy.\nIf you are looking for MAT (webui) then change your port to 8080.\nIf you are looking for the api then its /mop")
    
@app.get("/{path:path}", summary="External Endpoint")
async def external_endpoint_get(request: Request, path: str):
    """
    GET variant of external endpoints
    """
    try:
        response: dict = await utils.external_endpoint(path, "GET").call({})
    except NotImplementedError:
        if request.headers.get("Accept", "text/plain") == "application/json":
            return JSONResponse({"status": f"External endpoint at {path} is not implemented"}, status_code=404)
        return PlainTextResponse("404 Not Found", status_code=404)
        
    content = response.get("content", "")
    
    status_code = response.get("status", 200) if not content == "" else response.get("status", 204)
    
    header: dict = response.get("headers", {})
    
    mime_type: str = header.get("Content-Type", response.get("mime_type", "application/octet-stream" ))
    
    return Response(content, status_code=status_code, headers=header, media_type=mime_type)
    
@app.post("/{path:path}", summary="External Endpoint")
async def external_endpoint_post(request: Request, path: str):
    """
    POST variant of external endpoints
    """
    try:
        response: dict = await utils.external_endpoint(path, "GET").call(await request.json())
    except NotImplementedError:
        if request.headers.get("Accept", "text/plain") == "application/json":
            return JSONResponse({"status": f"External endpoint at {path} is not implemented"}, status_code=404)
        return PlainTextResponse("404 Not Found", status_code=404)
    except json.JSONDecodeError:
        return JSONResponse({"status": "Invalid JSON", "code": 1}, 400)
        
    content = response.get("content", "")
    
    status_code = response.get("status", 200) if not content == "" else response.get("status", 204)
    
    header: dict = response.get("headers", {})
    
    mime_type: str = header.get("Content-Type", response.get("mime_type", "application/octet-stream" ))
    
    return Response(content, status_code=status_code, headers=header, media_type=mime_type)


mop_prefix = "/mop"
mop_routes = [r for r in app.router.routes if getattr(r, "path", "").startswith(mop_prefix)]
other_routes = [r for r in app.router.routes if not getattr(r, "path", "").startswith(mop_prefix)]
app.router.routes = mop_routes + other_routes

if __name__ == "__main__":
    if sys.platform != "win32":
        import uvloop # pyright: ignore[reportMissingImports]
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy()) # pyright: ignore[reportAttributeAccessIssue]
    
    if not Path(args.cwd).expanduser().absolute().exists():
        print(f"{Fore.RED}ERROR{Fore.RESET}:    cwd directory does not exist: {args.cwd}")
        sys.exit(1)
        
    if not Path(args.cwd).expanduser().absolute().is_dir():
        print(f"{Fore.RED}ERROR{Fore.RESET}:    cwd is not a directory: {args.cwd}")
        sys.exit(1)
        
    
    ssl_cert, ssl_key = None, None
    use_legacy = args.legacy or not HAS_HYPERCORN
    if args.ssl:
        ssl_cert, ssl_key = get_certs()
    else:
        print(f"{Fore.YELLOW}WARNING{Fore.RESET}:  You are not using SSL. This is not recommended for production use. Use --ssl to enable SSL.")
        if not use_legacy:
            print(f"{Fore.YELLOW}WARNING{Fore.RESET}:  HTTP/2 requires SSL. Falling back to HTTP/1.1.")
            
    if sys.platform == "win32":
        print(f"{Fore.YELLOW}WARNING{Fore.RESET}:  Windows is not very well supported and is extremely unstable. Use Linux or WSL.")
        
    loop_impl: Literal["uvloop", "asyncio"] = "uvloop" if sys.platform != "win32" else "asyncio"
    
    steal_port(args.port)
    
    
    if use_legacy and not HAS_UVICORN:
        print(f"{Fore.RED}ERROR{Fore.RESET}: Uvicorn requested but not installed.")
        sys.exit(1)
        
    if not HAS_HYPERCORN and not HAS_UVICORN:
        print(f"{Fore.RED}ERROR{Fore.RESET}: No ASGI server (Hypercorn/Uvicorn) found.")
        sys.exit(1)

    if use_legacy:
        # --- UVICORN ENGINE (Legacy/Speed) ---
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Starting engine: UVICORN (HTTP/1.1)")
        loop_impl = "uvloop" if sys.platform != "win32" else "asyncio"
        uvi_config = uvicorn.Config( # pyright: ignore[reportPossiblyUnboundVariable]
            "mop:app",
            host=args.host,
            port=args.port,
            loop=loop_impl,
            ssl_keyfile=ssl_key if args.ssl else None,
            ssl_certfile=ssl_cert if args.ssl else None,
            workers=args.workers,
        )
        server = uvicorn.Server(config=uvi_config) # pyright: ignore[reportPossiblyUnboundVariable]
    else:
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Starting engine: HYPERCORN (HTTP/2 Support)")
        hyp_config = HyperConfig() # pyright: ignore[reportPossiblyUnboundVariable]
        hyp_config.bind = [f"{args.host}:{args.port}"]
        hyp_config.workers = args.workers
        hyp_config.alpn_protocols = ["h2", "http/1.1"]
        hyp_config.accesslog = "-"
        hyp_config.errorlog = "-"
        hyp_config.loglevel = "DEBUG"
        
        if args.ssl:
            hyp_config.certfile = ssl_cert
            hyp_config.keyfile = ssl_key

    try:
        if "mat" in manifest.keys(): # pyright: ignore[reportPossiblyUnboundVariable]
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Mat is running on http{'s' if args.ssl else ''}://{args.host}:8080")
        if use_legacy:
            server.run()  # pyright: ignore[reportPossiblyUnboundVariable]
        else:
            asyncio.run(hyper_serve(app, hyp_config))  # type: ignore[arg-type]
    except KeyboardInterrupt:
        colorama_init(convert=True)
        os.environ["CLICOLOR_FORCE"] = "1"
        print(f"{Fore.RED}ERROR{Fore.RESET}:    KeyboardInterrupt detected. Exiting...", flush=True)
    except Exception as e:
        colorama_init(convert=True)
        print(f"{Fore.RED}ERROR{Fore.RESET}:    {e}", flush=True)
    finally:
        colorama_init(convert=True)
        os.environ["CLICOLOR_FORCE"] = "1"
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Starting shutdown of core plugins...", flush=True)
        for name, plugin in core_plugins.items(): # pyright: ignore[reportPossiblyUnboundVariable]
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Terminating plugin {name}")
            handle = cast(subprocess.Popen, plugin["handle"])
            handle.terminate()
            start = time.time()
            while handle.poll() is None:
                if time.time() - start > 5:
                    # Escalate: force kill
                    print(f"{Fore.RED}WARNING{Fore.RESET}:  Plugin {name} is unresponsive. Killing.")
                    handle.kill()
                    break
                time.sleep(0.1)  # small sleep to avoid busy-waiting
            
            handle.wait()
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Plugin {name} terminated")
            
        for name, plugin in non_core_plugins.items(): # pyright: ignore[reportPossiblyUnboundVariable]
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Terminating plugin {name}")
            handle = cast(subprocess.Popen, plugin["handle"])
            handle.terminate()
            start = time.time()
            while handle.poll() is None:
                if time.time() - start > 5:
                    # Escalate: force kill
                    print(f"{Fore.RED}WARNING{Fore.RESET}:  Plugin {name} is unresponsive. Killing.")
                    handle.kill()
                    break
                time.sleep(0.1)  # small sleep to avoid busy-waiting
            
            handle.wait()
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Plugin {name} terminated")
            
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Plugins shutdown complete.")
        if IS_CONPTY_AVAILABLE:
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Starting .NET shutdown...")
            for session in sessions.values():
                term = cast(Terminal,session["tty"])
                pty = cast(conpty.ConPTYClient, term.pty) # type: ignore[name-defined]
                if isinstance(term.pty, conpty.ConPTYClient): # type: ignore[name-defined]
                    try:
                        pty.close() # pyright: ignore[reportAttributeAccessIssue, reportPossiblyUnboundVariable] # type: ignore[attr-defined]
                    except Exception:
                        pass # nosec
                    print(f"{Fore.GREEN}INFO{Fore.RESET}:     .NET ConPTY session pid:{pty.pid} closed.")
        else:
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Shutting down terminal sessions...")
            for session in sessions.values():
                term = cast(Terminal,session["tty"])
                term.close()
                print(f"{Fore.GREEN}INFO{Fore.RESET}:     Terminal session pid:{term.pid} closed.")
                
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Server shutdown complete.")