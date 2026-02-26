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
from typing import Literal, cast, BinaryIO, TextIO, Callable,  Any, Tuple, AsyncGenerator, Union, Optional
import warnings
import shutil
import base64
from contextlib import asynccontextmanager
import random
import binascii

def is_pypy():
    return '__pypy__' in sys.builtin_module_names

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
    print("[INFO] Is PyPy: " + str(is_pypy()))
    print("[INFO] Found Moppy: " + str(moppy_path()[0]))
    
    if is_pypy():
        print("[WARNING] PyPy is not widely supported")
        if sys.platform == "win32":
            print("[WARNING] Disabling ConPTY python.net wrapper due to PyPy")
        else:
            print("[WARNING] Disabling uvloop due to PyPy")
    
    

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
    
    if sys.platform != "win32" and not is_pypy():
        required_packages.append("uvloop")
    elif sys.platform == "win32" and not is_pypy():
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
    print("[INFO] All MOP packages are installed! Checking for core plugin dependencies... (and you got color back. Hooray!)")    
    
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
import moppy.utils as utils # pyright: ignore[reportMissingImports]  # noqa: E402
import base91 # pyright: ignore[reportMissingImports] # noqa: E402
import moppy.hints as hints # pyright: ignore[reportMissingImports]  # noqa: E402
import moppy.backends.loader as loader # noqa: E402
from uuid import uuid4 as uuid_obj # noqa: E402

def uuid():
    return str(uuid_obj())

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
parser.add_argument("--debug", default=False, action="store_true", help="Enables debug logging for IPC operations and other internal processes. This may cause a performance decrease and should only be used for debugging purposes.")
args = parser.parse_args()

try:
    f_pepper: BinaryIO 
    with open(moppy_dir("pepper"), "rb") as f_pepper:
        f_pepper = cast(BinaryIO, f_pepper)
        pepper = bytes(base91.decode(f_pepper.read().split("🌶️".encode("utf-8"))[0]))
    
    if sys.platform != "win32":
        os.chmod(moppy_dir("pepper"), 0o600)
except FileNotFoundError:
    # Salt isnt found/generated yet
    pepper = secrets.token_bytes(32)
    f_pepper2: BinaryIO
    with open(moppy_dir("pepper"), "wb") as f_pepper2:
        f_pepper2 = cast(BinaryIO, f_pepper2)
        f_pepper2.write(base91.encode(pepper).encode("utf-8") + "🌶️".encode("utf-8"))
        
    if sys.platform != "win32":
        os.chmod(moppy_dir("pepper"), 0o600)
            
pem_count = len(list(moppy_dir("certs").glob("*.pem")))

is_ssl_certs_exists = pem_count >= 1            

if args.ssl and not is_ssl_certs_exists:
    print(f"{Fore.RED}ERROR{Fore.RESET}:    .pem or .key file missing in /moppy/certs")
    prompt = input(f"{Fore.YELLOW}WARNING{Fore.RESET}:  Generate new SSL certificates? (y/n): ")
    if prompt.lower() != "y":
        print(f"{Fore.YELLOW}INFO{Fore.RESET}:     Exiting... Remove --ssl to disable SSL.")
        sys.exit(1)
    os.system(sys.executable + str(moppy_dir("ssl_certs.py")))  

config = loader.read_config()

terminal_name = config.get("Backend", {}).get("Terminal", "default")
datastore_name = config.get("Backend", {}).get("Datastore", "default")

Terminal_Module = loader.load_terminal(terminal_name)
spawn_tty: Callable = Terminal_Module.spawn_tty # type: ignore
spawn_pipe: Callable = Terminal_Module.spawn_pipe # type: ignore
Terminal: hints.Terminal = Terminal_Module.Terminal # type: ignore

Datastore_Module = loader.load_datastore(datastore_name)
Datastore: hints.Datastore | type = Datastore_Module.Datastore # pyright: ignore[reportAssignmentType]

if sys.platform == "win32" and "win32" not in Terminal_Module.metadata["os_supported"]:
    print(f"{Fore.RED}ERROR{Fore.RESET}:    Windows is not supported with current Terminal backend")
elif "unix" not in Terminal_Module.metadata["os_supported"]: 
    print(f"{Fore.RED}ERROR{Fore.RESET}:    Unix-like is not supported with current Terminal backend")
    
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
        
        utils.steal_port(plugin["port"], args.force_port)
        
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
        
        utils.steal_port(plugin["port"], args.force_port)
        
        cmd = shlex.split(runtime)
        if "ssl" in plugin["supports"] and args.ssl:
            cert, key = cast(tuple[str, str], get_certs())
            cmd.append("--ssl-certfile")
            cmd.append(str(Path(cert).absolute()))
            cmd.append("--ssl-keyfile")
            cmd.append(str(Path(key).absolute()))
        non_core_plugins[name]["handle"] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=mop_cwd) # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Starting plugin:", name + f" at port {plugin['port']}" if plugin["port"] else "")
        non_core_plugin_handle = cast(subprocess.Popen, core_plugins[name]["handle"])
        time.sleep(0.5)
        if non_core_plugin_handle.poll() is None:
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     {name} is running!")
        else:
            assert non_core_plugin_handle.stdout is not None, "Did you remove the pipe for stdout?"
            assert non_core_plugin_handle.stderr is not None, "Did you remove the pipe for stderr?"
            print(f"{Fore.RED}ERROR{Fore.RESET}:    {name} failed to start!")
            print(f"{Fore.RED}ERROR{Fore.RESET}:    Stdout: {non_core_plugin_handle.stdout.read().decode('utf-8', replace=True)}")
            print(f"{Fore.RED}ERROR{Fore.RESET}:    Stderr: {non_core_plugin_handle.stderr.read().decode('utf-8', replace=True)}")
            sys.exit(1)
            
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     All non-core plugins are running!")
    
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Running required scripts...")
    
    scripts = moppy_dir("scripts").glob("*.py")
    
    for script in scripts:
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Running script: {script}")
        handle = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        handle.wait()
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
        print(f"{Fore.YELLOW}WARNING{Fore.RESET}:  You are using a python version that has deprecated the asyncio.set_event_loop_policy. This may cause issues. Please use 3.13.2 or lower.")
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy()) # pyright: ignore[reportAttributeAccessIssue] Stub doesnt have it 
else:
    if sys.version_info < (3, 14) and not is_pypy():
        import uvloop # pyright: ignore[reportMissingImports]
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy()) # pyright: ignore[reportAttributeAccessIssue] 
    elif not is_pypy():
        import uvloop # pyright: ignore[reportMissingImports]
        if __name__ == "__main__": # Show it once
            print(f"{Fore.YELLOW}WARNING{Fore.RESET}:  You are using a python version that has deprecated the asyncio.set_event_loop_policy. This may cause issues. Please use 3.13.2 or lower.")
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy()) # pyright: ignore[reportAttributeAccessIssue] Stub still doesnt have it 
    

sessions: hints.Session_storage = {}
powers: hints.Power_storage = {}

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
        if "DEBUG" not in message:
            self.original.write(message)
        elif args.debug and "DEBUG" in message:
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
    
def big_hash(s) -> str:
    if s is None: 
        return ""
    b = s if isinstance(s, bytes) else str(s).encode("utf-8")
    return hashlib.sha512(pepper + b).hexdigest()
    
logger = logging.getLogger("mop")

new_stdout: hints.TextStream = StreamToLogger(sys.stdout, logger, logging.INFO)
new_stderr: hints.TextStream = StreamToLogger(sys.stderr, logger, logging.ERROR)
sys.stdout = cast(StreamToLogger, new_stdout)
sys.stderr = cast(StreamToLogger, new_stderr)

command = shlex.split(args.cmd)
pub_key = big_hash(pepper)

global app

async def datastore_worker():
    datastore = app.state.manager
    while True:
        # Check the queue for new requests
        req = datastore.check_requests()
        if req is not None:
            # Do something with the request
            payload: dict = req.get("payload", {})
            to: int = req.get("from", "")
            id: str = req.get("id", "")
            operation: str = payload.get("Operation", "Existance")
            key: str = payload.get("key", "") # Key is prehashed
            print(f"{Fore.WHITE}DEBUG{Fore.RESET}:    Got request {operation} from {to}")
            match req["payload"]["Operation"]:
                case "Alias":
                    response = await mop_handlers.MopAlias(key)
                    alias = response[0]["alias"]
                    datastore.response(to, key, {"alias": alias}, id)
                case "Existance": # Basically a NOP
                    pass
                case "AtticTell":
                    info = payload.get("info")
                    response = await mop_handlers.MopAtticTell(key, info)
                    out = response[0]["attic_response"]
                    datastore.response(to, key, {"out": out}, id)
                case "GetTags":
                    response = await mop_handlers.MopCosmeticsGet_tags(key)
                    tags = response[0]["tags"]
                    datastore.response(to, key, {"tags": tags}, id)
                case "SetTags":
                    tags = payload.get("tags")
                    response = await mop_handlers.MopCosmeticsSet_tags(key, tags)
                    datastore.response(to, key, {"payload": response[0], "status_code": response[1]}, id)
                case "SetAttic":
                    response = await mop_handlers.MopSet_attic(key)
                    datastore.response(to, key, {"payload": response[0], "status_code": response[1]}, id)
                case "Stream":
                    is_alive = payload.get("is_alive")
                    if not is_alive or key not in sessions:
                        datastore.response(to, key, {"stdout": "", "stderr": ""}, id)
                        continue

                    buffers = sessions[key]["buffers"]
                    stdout_buffer: utils.ByteLimitedLog = buffers.get("stdout", utils.ByteLimitedLog())
                    stderr_buffer: utils.ByteLimitedLog = buffers.get("stderr", utils.ByteLimitedLog())
                    stdout_full: list[str] = stdout_buffer.buffer()
                    stderr_full: list[str] = stderr_buffer.buffer()

                    cursor_key = f"stream_cursor:{to}:{key}"
                    cursor = datastore.get_server_value(cursor_key, {"stdout": 0, "stderr": 0})
                    last_stdout = int(cursor.get("stdout", 0))
                    last_stderr = int(cursor.get("stderr", 0))

                    if last_stdout > len(stdout_full):
                        last_stdout = 0
                    if last_stderr > len(stderr_full):
                        last_stderr = 0

                    waivers = sessions[key].get("waivers", set())
                    stdout_chunks = stdout_full[last_stdout:]
                    stderr_chunks = stderr_full[last_stderr:]

                    if utils.Waiver.RAW_ANSI in cast(set[Any], waivers):
                        out_stdout = _merge_raw_ansi_chunks(stdout_chunks)
                        out_stderr = _merge_raw_ansi_chunks(stderr_chunks)
                    else:
                        out_stdout = "".join(stdout_chunks)
                        out_stderr = "".join(stderr_chunks)
                    datastore.set_server_value(cursor_key, {"stdout": len(stdout_full), "stderr": len(stderr_full)})
                    datastore.response(to, key, {"stdout": out_stdout, "stderr": out_stderr}, id)
                case "Write":
                    data = payload.get("data")
                    waivers = payload.get("waivers", [])
                    newline = payload.get("newline", False)
                    response = await mop_handlers.Write(key, data, waivers if waivers else None, newline)
                    datastore.response(to, key, {"payload": response[0], "status_code": response[1]}, id)
                case "Signal":
                    signal = payload.get("signal", "")
                    response = await mop_handlers.MopSignal(key, signal)
                    datastore.response(to, key, {"payload": response[0], "status_code": response[1]}, id)
                case "End":
                    pickle_data = payload.get("pickle", {})
                    response = await mop_handlers.MopEnd(key, pickle_data)
                    datastore.response(to, key, {"payload": response[0], "status_code": response[1]}, id)
                case "Read":
                    response = await mop_handlers.MopRead(key)
                    datastore.response(to, key, {"payload": response[0], "status_code": response[1]}, id)
                case "Waiver":
                    waivers = payload.get("waivers", {})
                    remove = payload.get("remove", [])
                    response = await mop_handlers.MopWaiver(key, waivers, remove)
                    datastore.response(to, key, {"payload": response[0], "status_code": response[1]}, id)
                case "Ping":
                    response = await mop_handlers.MopPing(key)
                    datastore.response(to, key, {"payload": response[0], "status_code": response[1]}, id)
                case "WebsocketConnection":
                    app.state.manager.unregister(key)
                case _: # Another NOP
                    pass
                
        await asyncio.sleep(0.1)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await asyncio.sleep(random.uniform(0.01, 0.1)) # nosec B311
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     {os.getpid()} - Connecting to Manager", flush=True) # pyright: ignore[reportAttributeAccessIssue]
    app.state.manager = cast(hints.Datastore, Datastore(authkey=b"test")) # type: ignore
    if app.state.manager.get_server_value("start_time") is None:
        app.state.manager.set_server_value("start_time", app.state.start_time)
    if app.state.manager.get_server_value("server_id") is None:
        app.state.manager.set_server_value("server_id", server_id)
    app.state.manager.set_server_value(f"worker:{os.getpid()}", {"sessions": len(sessions.keys()), "pending_writes": 0})
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     {os.getpid()} - Starting datastore worker", flush=True) # pyright: ignore[reportAttributeAccessIssue]
    logger.info(f"{os.getpid()}")
    app.state.ipc_worker = asyncio.create_task(datastore_worker())
    yield
    app.state.ipc_worker.cancel()

def create_app(command: list[str]):
    app = FastAPI(title="MOP", description="A stdio <-> HTTP(s) bridge.", version="1.1.1", lifespan=lifespan)
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
            "summary": "MOP WebSocket Terminal Stream",
            "description": (
                "WebSocket endpoint for interactive terminal sessions.\n\n"
                "• **Server → Client:** JSON messages containing `stdout` and `stderr` arrays.\n"
                "• **Client → Server:** JSON messages containing `stdin` string input.\n\n"
                "Connection upgrades via HTTP `101 Switching Protocols`.\n\n"
                f"(AsyncAPI Portal)[http{'s' if args.ssl else ''}://127.0.0.1:{args.port}/asyncDocs]"
            ),
            "tags": ["MOP Power Endpoints"],
            "parameters": [
                {
                    "name": "key",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                    "description": "Alias for session key"
                }
            ],
            "responses": {
                "101": {
                    "description": "Switching Protocols – WebSocket connection established",
                    "headers": {
                        "Upgrade": {
                            "description": "Protocol upgrade header",
                            "schema": {
                                "type": "string",
                                "example": "websocket"
                            }
                        },
                        "Connection": {
                            "description": "Connection upgrade indicator",
                            "schema": {
                                "type": "string",
                                "example": "Upgrade"
                            }
                        },
                        "Sec-WebSocket-Accept": {
                            "description": "Server handshake response key",
                            "schema": {
                                "type": "string"
                            }
                        }
                    }
                },
                "400": {
                    "description": "Invalid request"
                },
                "403": {
                    "description": "Forbidden"
                }
            }
        }
    }

    # Ensure components exist
    openapi_schema.setdefault("components", {}).setdefault("schemas", {})

    # Server -> Client payload
    openapi_schema["components"]["schemas"]["TerminalOutput"] = {
        "type": "object",
        "properties": {
            "stdout": {
                "type": "string",
                "description": "New stdout lines",
                "example": "hahahaha i am in stdout"
            },
            "stderr": {
                "type": "string",
                "description": "New stderr lines",
                "example": "hahahaha i am in stderr"
            }
        }
    }

    # Client -> Server payload
    openapi_schema["components"]["schemas"]["TerminalInput"] = {
        "type": "object",
        "properties": {
            "stdin": {
                "type": "string",
                "pattern": r"^[^\r\n]*$",
                "description": "Raw input to send to terminal stdin",
                "example": "echo hello"
            },
            "newline": {
                "type": "boolean",
                "description": f"Appends a OS specific newline if true. ONLY MEANINGFUL IF STREAM_STDIN waiver is enabled. See [AsyncAPI](http{'s' if args.ssl else ''}://127.0.0.1:{args.port}/asyncDocs) for more detail",
                "example": True
            }
        },
        "required": ["stdin"]
    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema

mop_router = APIRouter(tags=["MOP endpoints"])

app.openapi = custom_openapi # type: ignore[method-assign]

app.state.start_time = time.monotonic()
app.state.pepper = pepper

@app.middleware("http")
async def log_worker(request: Request, call_next):
    if hasattr(app.state, "manager"):
        pending_writes = 0
        if pub_key in sessions:
            pending_writes = cast(hints.PubSession, sessions[pub_key])["queue"].qsize()
        app.state.manager.set_server_value(f"worker:{os.getpid()}", {"sessions": len(sessions.keys()), "pending_writes": pending_writes})
    print(f"{Fore.WHITE}DEBUG{Fore.RESET}:    Worker {os.getpid()} handling {Fore.GREEN}{request.method}{Fore.RESET} {request.url.path}")
    response = await call_next(request)
    return response

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


async def write(data: str, key: str, waivers: set[str | Any]):
    if key not in sessions:
        return {"status": "MOP transaction not started", "code": 1}, 428

    term: hints.Terminal = sessions[key]["tty"]  # Terminal object
    
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


def _merge_raw_ansi_chunks(chunks: list[str]) -> str:
    decoded_parts: list[bytes] = []
    for chunk in chunks:
        if not chunk:
            continue
        normalized = chunk + ("=" * ((4 - len(chunk) % 4) % 4))
        try:
            decoded_parts.append(base64.b64decode(normalized))
        except (binascii.Error, ValueError):
            return "".join(chunks)
    return base64.b64encode(b"".join(decoded_parts)).decode("ascii")

class mop_handlers:
    @staticmethod
    async def check_response(key, operation_id, timeout_seconds=3.0, poll_interval=0.05):
        start = time.monotonic()
        attempts = 0
        while time.monotonic() - start < timeout_seconds:
            attempts += 1
            print(f"{Fore.WHITE}DEBUG{Fore.RESET}:    Waiting for response for operation {operation_id[:4]} from {key[:6]}, attempt {attempts}")
            response = app.state.manager.check_response(key, operation_id)
            if response is not None:
                return response
            await asyncio.sleep(poll_interval)
        return None
    
    @staticmethod
    async def MopAlias(key):
        operation_id = uuid()
        
        if key not in sessions:
            status = app.state.manager.request(key, {"Operation": "Alias", "key": key}, operation_id)
            if not status:
                return {"status": "Invalid Key", "code": 1}, 404
            else:
                # this process doesnt own the key. need to use the manager
                response = await mop_handlers.check_response(key, operation_id)
                if response is None:
                    return {"status": "Encountered error with IPC", "code": 1}, 500
                alias = response.get("alias")
        else:
            # this process owns the key
            alias = secrets.token_hex(32)
            
            sessions[alias] = key # type: ignore
            app.state.manager.register(alias)
        
        return {"status": "Created Alias", "alias": alias, "code": 0}, 200
    
    @staticmethod
    async def MopValidate(key):
        operation_id = uuid()
        if key not in sessions:
            status = app.state.manager.request(key, {"Operation": "Existance", "key": key}, operation_id)
            if not status: # Status states if it was able to send the message or not. No message = invalid key
                return {"status": "Invalid key", "code": 1}, 404
                
        return {"status": "Key exists", "code": 0}, 200
    
    @staticmethod
    async def MopAtticTell(key, info):
        operation_id = uuid()
        if key not in sessions:
            status = app.state.manager.request(key, {"Operation": "AtticTell", "key": key, "info": info}, operation_id)
            if not status:
                return {"status": "Invalid key", "code": 1}, 404
            else:
                await asyncio.sleep(0.1) # give time to the operation. all overhead is the IPC
                response = await mop_handlers.check_response(key, operation_id)
                if response is None:
                    return {"status": "Encountered error with IPC", "code": 1}, 500
                out = response.get("out")
        else:
            try:
                out = utils.attic(key, sessions[key]["tty"].pid).tell(info)
            except Exception as e:
                return {"status": f"Failed to tell process data due to {str(e)}"}, 500
        
        return {"status": "Sucessfully got attic output","attic_response": out, "code": 0}, 200
    
    @staticmethod
    async def MopCosmeticsGet_tags(key):
        operation_id = uuid()
        if key not in sessions:
            status = app.state.manager.request(key, {"Operation": "GetTags", "key": key}, operation_id)
            if not status:
                return {"status": "Invalid key", "code": 1}, 404
            else:
                await asyncio.sleep(0.1)
                response = await mop_handlers.check_response(key, operation_id)
                if response is None:
                    return {"status": "Encountered error with IPC", "code": 1}, 500
                tags = response.get("tags")
        else:
            tags = sessions[key]["tags"]
        
        return {"tags": tags, "code": 0}, 200
    
    @staticmethod
    async def MopCosmeticsSet_tags(key, tags):
        operation_id = uuid()
        if key not in sessions:
            status = app.state.manager.request(key, {"Operation": "SetTags", "key": key, "tags": tags}, operation_id)
            if not status:
                return {"status": "Invalid key", "code": 1}, 404
            else:
                response = await mop_handlers.check_response(key, operation_id)
                if response is None:
                    return {"status": "Encountered error with IPC", "code": 1}, 500
                
        else:
            sessions[key]["tags"] = tags
        return {"status": "Tags updated", "code": 0}, 200
    
    @staticmethod
    async def MopSet_attic(key):
        operation_id = uuid()
        if key not in sessions:
            status = app.state.manager.request(key, {"Operation": "SetAttic", "key": key}, operation_id)
            if not status:
                return {"status": "Invalid key", "code": 1}, 404
            response = await mop_handlers.check_response(key, operation_id)
            if response is None:
                return {"status": "Encountered error with IPC", "code": 1}, 500
        else:
            session_copy = cast(hints.PrivSession, sessions[key]).copy()
            session_copy["attic"] = True
            sessions[key] = session_copy
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Attic flag set for {key[:6]}")
        return {"status": "Attic flag set", "code": 0}, 200

    @staticmethod
    async def MopSignal(key, signal):
        operation_id = uuid()
        signal_map = {
            "INTERRUPT": utils.Signal.INTERRUPT,
            "TERMINATE": utils.Signal.TERMINATE,
            "KILL": utils.Signal.KILL
        }
        if signal not in signal_map:
            return {"status": "Invalid signal", "code": 1}, 404

        if key not in sessions:
            status = app.state.manager.request(key, {"Operation": "Signal", "key": key, "signal": signal}, operation_id)
            if not status:
                return {"status": "Invalid key", "code": 1}, 404
            response = await mop_handlers.check_response(key, operation_id)
            if response is None:
                return {"status": "Encountered error with IPC", "code": 1}, 500
            return response.get("payload", {"status": "Signal sent", "code": 0}), response.get("status_code", 200)

        try:
            if signal in ("INTERRUPT", "TERMINATE", "KILL"):
                await sessions[key]["tty"].send_signal(signal_map[signal])
                cast(asyncio.Task, sessions[key]["task_out"]).cancel()
                cast(hints.Terminal, sessions[key]["tty"]).close()
            else:
                await sessions[key]["tty"].send_signal(signal_map[signal])
            del sessions[key]
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Sent signal {signal} to session {key[:6]}")
            if len(sessions) < 2 and pub_key in sessions:
                cast(hints.PubSession, sessions[pub_key])["task_out"].cancel()
                cast(hints.PubSession, sessions[pub_key])["queue"].put_nowait(None)
                cast(hints.PubSession, sessions[pub_key])["task_in"].cancel()
                cast(hints.PubSession, sessions[pub_key])["tty"].close()
                del sessions[pub_key]
                print(f"{Fore.GREEN}INFO{Fore.RESET}:     Killed public session {pub_key[:6]} due to no other sessions remaining")
            return {"status": "Signal sent", "code": 0}, 200
        except Exception:
            return {"status": "Failed to send signal", "code": 1}, 500

    @staticmethod
    async def MopEnd(key, pickle_data):
        operation_id = uuid()
        if key not in sessions:
            status = app.state.manager.request(key, {"Operation": "End", "key": key, "pickle": pickle_data}, operation_id)
            if not status:
                return {"status": "Invalid key", "code": 1}, 404
            response = await mop_handlers.check_response(key, operation_id)
            if response is None:
                return {"status": "Encountered error with IPC", "code": 1}, 500
            return response.get("payload", {"status": "Session ended", "code": 0}), response.get("status_code", 200)

        failed_to_store: str = ""
        term: hints.Terminal = sessions[key]["tty"]

        try:
            sessions[key]["task_out"].cancel()
        except Exception:
            pass

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
                    return {"status": "Terminal not found", "code": 1}, 500
                await term.send_signal(utils.Signal.TERMINATE)
                await term.proc.wait()
            except Exception:
                pass

        if not sessions[key].get("attic", False):
            del sessions[key]
        else:
            try:
                await utils.attic(key, term.pid).set(pickle_data)
                await asyncio.sleep(0.5)
            except Exception as e:
                failed_to_store = str(e)
            del sessions[key]

        if len(sessions) < 2 and pub_key in sessions and not args.no_pub_process:
            try:
                sessions[pub_key]["task_out"].cancel()
                cast(hints.PubSession, sessions[pub_key])["queue"].put_nowait(None)
                cast(hints.PubSession, sessions[pub_key])["task_in"].cancel()
            except Exception:
                pass
            pub_term: hints.Terminal = sessions[pub_key]["tty"]
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

        return {"status": f"Session ended{f' and failed to store to attic due to {str(failed_to_store)}' if failed_to_store else ''}", "code": 0}, 200

    @staticmethod
    async def MopRead(key):
        operation_id = uuid()
        if key not in sessions:
            status = app.state.manager.request(key, {"Operation": "Read", "key": key}, operation_id)
            if not status:
                return {"status": "Invalid key", "code": 1}, 404
            response = await mop_handlers.check_response(key, operation_id)
            if response is None:
                return {"status": "Encountered error with IPC", "code": 1}, 500
            return response.get("payload", {"status": "Invalid key", "code": 1}), response.get("status_code", 500)

        if cast(asyncio.Task, sessions[key]["task_out"]).done():
            return {"status": "Task reached EOF", "code": 1}, 500

        buffer_stdout: utils.ByteLimitedLog = sessions[key]["buffers"].get("stdout", utils.ByteLimitedLog())
        buffer_stderr: utils.ByteLimitedLog = sessions[key]["buffers"].get("stderr", utils.ByteLimitedLog())
        stdout: list = buffer_stdout.buffer()
        stderr: list = buffer_stderr.buffer()

        out: dict[str, list[str]] = {"stdout": stdout, "stderr": stderr}
        return {"stdout": out["stdout"], "stderr": out.get("stderr", ""), "code": 0, "output_hash": hashlib.md5(cast(memoryview, json.dumps(out, sort_keys=True).encode("utf-8")), usedforsecurity=False).hexdigest()}, 200 # nosec

    @staticmethod
    async def MopWaiver(key, waivers, remove):
        operation_id = uuid()
        if key not in sessions:
            status = app.state.manager.request(key, {"Operation": "Waiver", "key": key, "waivers": waivers, "remove": remove}, operation_id)
            if not status:
                return {"status": "Invalid key", "code": 1}, 404
            response = await mop_handlers.check_response(key, operation_id)
            if response is None:
                return {"status": "Encountered error with IPC", "code": 1}, 500
            return response.get("payload", {"status": "Waiver(s) set/removed", "code": 0}), response.get("status_code", 200)

        if not waivers:
            return {"status": "No waivers set", "code": 0}, 200

        for waiver, value in waivers.items():
            if waiver.lower() == "raw_ansi":
                cast(hints.PrivSession, sessions[key])["waivers"].add(utils.Waiver.RAW_ANSI)
            elif waiver.lower() == "b64_stdin":
                cast(hints.PrivSession, sessions[key])["waivers"].add(utils.Waiver.B64_STDIN)
            elif waiver.lower() == "stream_stdin":
                cast(hints.PrivSession, sessions[key])["waivers"].add(utils.Waiver.STREAM_STDIN)
            else:
                return {"status": f"Unknown waiver: {waiver}", "code": 1}, 404

        for waiver in remove:
            try:
                cast(hints.PrivSession, sessions[key])["waivers"].remove(waiver)
            except Exception:
                return {"status": "Unable to remove waiver", "code": 1}, 500

        return {"status": "Waiver(s) set/removed", "code": 0}, 200

    @staticmethod
    async def MopPing(key):
        operation_id = uuid()
        if key not in sessions:
            status = app.state.manager.request(key, {"Operation": "Ping", "key": key}, operation_id)
            if not status:
                return {"status": "Session not found", "code": 1}, 404
            response = await mop_handlers.check_response(key, operation_id)
            if response is None:
                return {"status": "Encountered error with IPC", "code": 1}, 500
            return response.get("payload", {"status": "Session not found", "code": 1}), response.get("status_code", 500)

        term: hints.Terminal = sessions[key]["tty"]
        if term.is_alive:
            return {"status": "Process is alive", "code": 0}, 200
        return {"status": "Process is terminated", "code": 1}, 410

    @staticmethod
    async def MopProcess():
        local_pending_writes = 0
        if pub_key in sessions:
            local_pending_writes = cast(hints.PubSession, sessions[pub_key])["queue"].qsize()
        app.state.manager.set_server_value(f"worker:{os.getpid()}", {"sessions": len(sessions.keys()), "pending_writes": local_pending_writes})

        app.state.manager.set_server_value("process_meta", {
            "command": list(app.state.command),
            "server_id": app.state.manager.get_server_value("server_id", server_id),
            "pub_key": pub_key,
            "version": "1.1.1",
            "start_time": app.state.manager.get_server_value("start_time", app.state.start_time),
        })

        response = {
            "status": "No process is running.",
            "server_id": app.state.manager.get_server_value("server_id", server_id),
            "command": list(app.state.command),
            "uptime": f"{int(time.monotonic() - float(app.state.manager.get_server_value('start_time', app.state.start_time)))}",
            "version": "1.1.1",
            "code": 0
        }

        worker_data = app.state.manager.get_server_data()
        total_sessions = 0
        total_pending_writes = 0
        for worker, stats in worker_data.items():
            if not str(worker).startswith("worker:"):
                continue
            total_sessions += int(stats.get("sessions", 0))
            total_pending_writes += int(stats.get("pending_writes", 0))

        if total_sessions > 0:
            response = {
                "command": list(app.state.command),
                "server_id": app.state.manager.get_server_value("server_id", server_id),
                "sessions": total_sessions,
                "pub_key": pub_key,
                "pending_writes": total_pending_writes,
                "uptime": f"{int(time.monotonic() - float(app.state.manager.get_server_value('start_time', app.state.start_time)))}",
                "version": "1.1.1",
                "code": 0
            }
            return response, 200
        return response, 428

    @staticmethod
    async def StreamRead(key, is_alive):
        last_stdout = 0 # type: ignore
        last_stderr = 0 # type: ignore
        operation_id = uuid()
        local_key = True
        
        async def read_output(key: str, local_key: bool = True):
            nonlocal last_stdout, last_stderr
            current_stdout = ""
            current_stderr = ""
            if local_key:
                session = sessions[key]
                waivers = cast(hints.PrivSession, session)["waivers"]
                stdout: utils.ByteLimitedLog = session["buffers"].get("stdout", utils.ByteLimitedLog())
                new_stdout: list = stdout.buffer()
                if len(new_stdout) == 0 or last_stdout == len(new_stdout): # type: ignore
                    current_stdout = ""
                else:
                    stdout_chunks = cast(list[str], new_stdout[last_stdout:]) # type: ignore
                    if utils.Waiver.RAW_ANSI in cast(set[Any], waivers):
                        current_stdout = _merge_raw_ansi_chunks(stdout_chunks)
                    else:
                        current_stdout = "".join(stdout_chunks)
                last_stdout = len(new_stdout) # type: ignore   
                stderr: utils.ByteLimitedLog = sessions[key]["buffers"].get("stderr", utils.ByteLimitedLog())
                new_stderr: list = stderr.buffer()
                if len(new_stderr) == 0 or last_stderr == len(new_stderr): # type: ignore
                    current_stderr = ""
                else:
                    stderr_chunks = cast(list[str], new_stderr[last_stderr:]) # type: ignore
                    if utils.Waiver.RAW_ANSI in cast(set[Any], waivers):
                        current_stderr = _merge_raw_ansi_chunks(stderr_chunks)
                    else:
                        current_stderr = "".join(stderr_chunks)
                last_stderr = len(new_stderr) # type: ignore
                return current_stdout, current_stderr
            else:
                request = app.state.manager.request(key, {"Operation": "Stream", "key": key, "is_alive": is_alive}, operation_id)
                if not request:
                    return "", ""
                await asyncio.sleep(0.1) # give time
                response = await mop_handlers.check_response(key, operation_id)
                if response is None:
                    return "", ""
                current_stdout = response.get("stdout", "")
                current_stderr = response.get("stderr", "")
                return current_stdout, current_stderr
        
        if key not in sessions:
            status = app.state.manager.request(key, {"Operation": "Existance", "key": key}, uuid())
            if not status:
                return {"status": "Invalid Key", "code": 1}, None, 404
            else:
                local_key = False

        async def sse_generator():
            heartbeat_timer = time.monotonic()
            while True:
                # 2. Check for disconnect (Stop wasting CPU if they leave)
                if not is_alive:
                    break
                
                # 3. Pull from your existing stdout buffer
                stdout, stderr = await read_output(key, local_key)

                if not stdout == "" or not stderr == "":
                    # SSE Format: "data: <content>\n\n"
                    response = json.dumps({"stdout": stdout, "stderr": stderr})
                    yield f"data: {response}\n\n"
                else:
                    if time.monotonic() - heartbeat_timer > 14.5: # About 15 seconds
                        heartbeat_timer = time.monotonic()
                        yield ": heartbeat\n\n"
                        continue

                # 4. Small sleep to prevent CPU spinning
                await asyncio.sleep(0.1)
        
        async def ipc_generator():
            while True:
                # 2. Check for disconnect (Stop wasting CPU if they leave)
                if not is_alive:
                    break
                
                # 3. Pull from your existing stdout buffer
                stdout, stderr = await read_output(key, local_key)

                if not stdout == "" or not stderr == "":
                    # SSE Format: "data: <content>\n\n"
                    response = {"stdout": stdout, "stderr": stderr}
                    yield response

                # 4. Small sleep to prevent CPU spinning
                await asyncio.sleep(0.1)

        return sse_generator(), ipc_generator(), 200
    
    @staticmethod
    async def Write(key, data, waivers=None, newline=False):
        operation_id = uuid()
        if key not in sessions:
            status = app.state.manager.request(
                key,
                {"Operation": "Write", "key": key, "data": data, "waivers": list(waivers) if waivers is not None else [], "newline": newline},
                operation_id
            )
            if not status:
                return {"status": "Invalid Key", "code": 1}, 404
            await asyncio.sleep(0.1) # give time
            response = await mop_handlers.check_response(key, operation_id)
            if response is None:
                return {"status": "Encountered error with IPC", "code": 1}, 500
            return response.get("payload", {"status": "Wrote data", "code": 0}), response.get("status_code", 200)
        else:
            if waivers is None:
                waivers = cast(hints.PrivSession, sessions[key])["waivers"].copy()
            else:
                waivers = set(waivers)
            if newline and utils.Waiver.STREAM_STDIN in waivers:
                waivers.remove(utils.Waiver.STREAM_STDIN)
            write_response = await write(data, key, waivers)
            return write_response
    
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
    
    if use_pipe and "pipe" not in Terminal_Module.metadata["method_supported"]:
        return JSONResponse({"status": "Current terminal backend does not support pipes", "code": 1}, 400)
    elif not use_pipe and "pty" not in Terminal_Module.metadata["method_supported"]:
        return JSONResponse({"status": "Current terminal backend does not support pty. Call with use_pipe instead", "code": 1}, 400)
    
    if request.client is None:
        return JSONResponse({"status": "request.client is None", "comment": "Youre just as confused as i am. Blame Pylance", "code": 1},500)
    
    if not use_pipe:
        process_handle = await spawn_tty(command, not echo)
    else:
        process_handle = await spawn_pipe(command)
    
    
    async def OUT_reader(default_key: str) -> None:
        buffers: hints.buffers_dict = sessions[default_key]["buffers"]
        tty: hints.Terminal = sessions[default_key]["tty"]
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

                if stdout:
                    buffers["stdout"].append(stdout)
                if stderr:
                    buffers["stderr"].append(stderr)

            except Exception as e:
                buffers["stdout"].append(f"[ERROR reading stdout: {e}]")
                print(f"{Fore.GREEN}ERROR{Fore.RESET}:    {e}")
                break
            
    async def IN_pub_writer(pub_key: str):
        session: hints.PubSession = cast(hints.PubSession, sessions[pub_key])
        tty: hints.Terminal = session["tty"]
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
        pub_process_handle: hints.Terminal = await spawn_tty(app.state.command, not echo)
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
            return {"status": "Error retrieving attic", "code": 1, "error": str(e)}, 500
    
    client = f"{request.client.host}:{request.client.port}" # pyright: ignore[reportOptionalMemberAccess]
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
    app.state.manager.register(hashed_key)
    return JSONResponse(response, 200)
    

@mop_router.post("/mop/alias", summary="Temporary Key", responses=hints.responses.MopAlias())
@ratelimit("1/minute", "Ratelimit of 1 RPM")
async def temporary_keys(options: hints.models.MopAlias):
    """
    Generates a temporary alias for your key.

    This alias when connected to a endpoint that requires this alias
    
    The alias for the public session is always "Public".
    
    Endpoints that currently use this alias:
    
     - /mop/power/sock/{key_alias}
    """
    
    if options.key == pub_key:
        response = ({"status": "Created Alias", "alias": "Public", "comment": "Save time by just using the alias 'Public' for the public session", "code": 0}, 200)
    else:
        response = await mop_handlers.MopAlias(big_hash(options.key))
    
    return JSONResponse(*response)

@mop_router.post("/mop/validate", summary="Validate key", responses=hints.responses.MopValidate())
@ratelimit("10/minute", "Ratelimit of 10 RPM")
async def validate(options: hints.models.MopValidate):
    """
    Validates your keys.
    """
    key: str = options.key
    if key == pub_key:
        response = ({"status": "Public key", "code": 0}, 200)
    else:
        response = await mop_handlers.MopValidate(big_hash(key))
    return JSONResponse(*response)
    

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
    response = await mop_handlers.MopAtticTell(hashed_key, info)
    
    return JSONResponse(*response)

@mop_router.post("/mop/cosmetics/get_tags", responses=hints.responses.MopCosmeticsGet_tags())
async def get_tags(options: hints.models.MopCosmeticsGet_tags):
    """
    Get tags for your session
    """
    key: str = big_hash(options.key)
    
    response = await mop_handlers.MopCosmeticsGet_tags(key)
    
    return JSONResponse(*response)

@mop_router.post("/mop/cosmetics/set_tags", responses=hints.responses.MopCosmeticsSet_tags())
async def set_tags(options: hints.models.MopCosmeticsSet_tags):
    """
    Set tags for your session
    """
    key: str = big_hash(options.key)
    if options.key == pub_key:
        return JSONResponse({"status": "Cannot set tags for public key", "code": 1}, status_code=403)
    
    response = await mop_handlers.MopCosmeticsSet_tags(key, options.tags)
    return JSONResponse(*response)

@mop_router.post("/mop/set_attic", responses=hints.responses.MopSet_attic())
async def persist_session(options: hints.models.MopSet_attic):
    """
    Sets the attic flag so your session will be marked as persistent.
    """
    key: str = options.key
    hashed_key: str = big_hash(key)
    if key == pub_key:
        return JSONResponse({"status": "Cannot set attic flag for public key", "code": 1}, status_code=403)
    
    response = await mop_handlers.MopSet_attic(hashed_key)
    
    return JSONResponse(*response)

@mop_router.post("/mop/power/stream/read", summary="SSE stdout", responses=hints.responses.MopPowerStreamRead(), tags=["MOP Power Endpoints"])
async def sse_read(options: hints.models.MopPowerStreamRead, request: Request):
    """
    SSE stdout stream
    """
    async def error_generator(output, is_alive):
        while True:
            if not is_alive:
                break
            yield json.dumps(output)
            await asyncio.sleep(0.1)
     
    is_disconnected = await request.is_disconnected()
    untyped_event_generator, _, code = await mop_handlers.StreamRead(big_hash(options.key), not is_disconnected)
    event_generator = cast(Union[AsyncGenerator, Callable], untyped_event_generator)
    if isinstance(untyped_event_generator, dict):
        event_generator = error_generator(untyped_event_generator, not is_disconnected)
    return StreamingResponse(event_generator, media_type="text/event-stream", status_code=code) # type: ignore

@app.websocket("/mop/power/sock/{key}")
async def power_sock(websocket: WebSocket, key: str):
    alias = key
    if alias not in sessions and not alias == "Public":
        await websocket.close(code=1008, reason="Invalid Alias")
        return
    
    is_pub_key = False
    
    if alias == "Public":
        is_pub_key = True
        hashed_key = pub_key
    else:
        if alias not in sessions:
            status = app.state.manager.request(alias, {"Operation": "WebsocketConnection", "key": alias}, uuid())
            if not status:
                await websocket.close(code=1008, reason="Invalid Alias")
                return
            hashed_key = sessions[alias] # type: ignore
        else:
            hashed_key = sessions[alias] # type: ignore
            app.state.manager.unregister(alias)
            del sessions[alias]
    
    
    await websocket.accept()
    if websocket.client is None:
        await websocket.close(code=1011, reason="Websocket.client is None. P.S. Contact the server owner about this issue")
        return
    client = f"{websocket.client.host}:{websocket.client.port}"
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     {client} - Session {hashed_key[:6]} connected") # pyright: ignore[reportGeneralTypeIssues]
    
    try:
        async def send_to_client() -> None:
            stream = await mop_handlers.StreamRead(hashed_key, True)
            sse_generator: Union[AsyncGenerator, dict] = stream[0] # type: ignore
            ipc_generator: Optional[AsyncGenerator] = stream[1] # type: ignore
            status_code: int = stream[2] # type: ignore
            if isinstance(sse_generator, dict) or status_code != 200:
                sse_generator["http_status_code"] = status_code # type: ignore
                await websocket.send_text(json.dumps(sse_generator))
                await websocket.close(code=1011, reason="Encountered error while reading from session.")
                return
            assert ipc_generator is not None, "StreamRead should return an ipc_generator if there is no error"
            while True:
                try:
                    buffers: dict[str, str] = await anext(ipc_generator)
                except StopAsyncIteration:
                    break
                stdout = buffers.get("stdout", "")
                stderr = buffers.get("stderr", "")

                if stdout or stderr:
                    payload = {
                        "stdout": stdout, 
                        "stderr": stderr
                    }
                    try:
                        await websocket.send_text(json.dumps(payload))
                    except RuntimeError: # Websocket is closed. Ignore
                        pass

                await asyncio.sleep(0.1)
                
        async def receive_from_client() -> None:
            last_time = time.monotonic()
            while True:
                received_data = await websocket.receive_text()
                
                try:
                    stdin: dict = json.loads(received_data)
                except json.JSONDecodeError:
                    await websocket.close(code=1008)
                    print(f"{Fore.GREEN}ERROR{Fore.RESET}:    Client {client} didn't send JSON")
                    return
                
                data = stdin["stdin"]
                        
                
                # Rate limiting / Backpressure
                now = time.monotonic()
                count = 0.0
                count = max(0.0, count - (now - last_time) * 50)
                last_time = now
                count += 1

                if count > 50:
                    await websocket.close(code=1008, reason="Ratelimit exceeded")
                    print(f"{Fore.GREEN}ERROR{Fore.RESET}:    Ratelimit exceeded for {client}")
                
                if is_pub_key:
                    # Use the global pub_key session queue
                    cast(hints.PubSession, sessions[pub_key])["queue"].put_nowait(data)
                else:
                    newline = stdin.get("newline", False)
                    waivers = cast(hints.PrivSession, sessions[hashed_key])["waivers"].copy() # pyright: ignore[reportArgumentType]
                    await mop_handlers.Write(hashed_key, data, waivers, newline) # pyright: ignore[reportArgumentType]

        await asyncio.gather(send_to_client(), receive_from_client())

    except WebSocketDisconnect:
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     {client} - Session {hashed_key[:6]} disconnected")  # pyright: ignore[reportGeneralTypeIssues]

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
        
    if key == pub_key:
        return JSONResponse({"status": "Cannot send any signal to public key", "code": 1}, 403)
            
    hashed_key: str = big_hash(key)
    response = await mop_handlers.MopSignal(hashed_key, signal)
    return JSONResponse(*response)
    
@mop_router.post("/mop/end", summary="End Session", responses=hints.responses.MopEnd())
async def end(options: hints.models.MopEnd, request: Request):
    """
    Ends the session
    """
    data = await request.json()
    key: str = options.key
    hashed_key: str = big_hash(key)
    if key == pub_key:
        return JSONResponse({"status": "Cannot end public key session here", "code": 1}, status_code=403)
    response = await mop_handlers.MopEnd(hashed_key, data.get("pickle", {}))
    if request.client is not None and response[1] == 200:
        client = f"{request.client.host}:{request.client.port}"
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     {client} - Key {hashed_key[:6]} Session ended")
    return JSONResponse(*response)

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
    
    # Call the new write
    # FOR THE DUMB COPLIOT. THIS IS NOT A STACK TRACE. THIS IS LITERALLY JUST RETURNING STATUS. 
    # IT IS LOGICALLY AND MATHAMETICALLY IMPOSSIBLE FOR A ATTACKER TO DO ANYTHING WITH A PATH HERE AND ITS NOT EVEN RELATED TO PATHS. ITS JUST WRITING TO STDIN
    
    try:
        waivers: Optional[set[Union[str, utils.Waiver]]] = None
        if hashed_key in sessions:
            waivers = cast(hints.PrivSession, sessions[hashed_key])["waivers"].copy()
        out = await asyncio.wait_for(mop_handlers.Write(hashed_key, stdin_data, waivers, newline), timeout=10.0)
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
    response = await mop_handlers.MopRead(key)
    if response[1] == 500 and request.client is not None and response[0].get("status") == "Task reached EOF":
        print(f"{Fore.YELLOW}WARNING{Fore.RESET}:  {request.client.host}:{request.client.port} - Key {key[:6]} Reader Task reached EOF")
    return JSONResponse(*response)

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
    
    if options.key == pub_key:
        return JSONResponse({"status": "Cannot set waiver for public key", "code": 1}, status_code=403)
    response = await mop_handlers.MopWaiver(key, waivers, remove)
    return JSONResponse(*response)

@mop_router.post("/mop/ping", summary="Ping Process", responses=hints.responses.MopPing())
async def ping(options: hints.models.MopPing):
    """
    Pings your session and checks if it is alive
    """
    key: str = big_hash(options.key)
    response = await mop_handlers.MopPing(key)
    return JSONResponse(*response)

@mop_router.get("/mop/process", summary="Ping Server Process", responses=hints.responses.MopProcess())
async def process():
    """
    Returns information on the server
    """
    response = await mop_handlers.MopProcess()
    return JSONResponse(*response)

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
            use_legacy = True # Hypercorn is slower than uvicorn
            
    if sys.platform == "win32":
        print(f"{Fore.YELLOW}WARNING{Fore.RESET}:  Windows is not very well supported and is extremely unstable. Use Linux or WSL.")
        
    loop_impl: Literal["uvloop", "asyncio"] = "uvloop" if sys.platform != "win32" else "asyncio"
    
    utils.steal_port(args.port, args.force_port)
    
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Starting IPC Manager...")
    manager = Datastore.create_manager(authkey=b"test") # type: ignore
    
    
    if use_legacy and not HAS_UVICORN:
        print(f"{Fore.RED}ERROR{Fore.RESET}: Uvicorn requested but not installed.")
        sys.exit(1)
        
    if not HAS_HYPERCORN and not HAS_UVICORN:
        print(f"{Fore.RED}ERROR{Fore.RESET}: No ASGI server (Hypercorn/Uvicorn) found.")
        sys.exit(1)

    if use_legacy:
        # --- UVICORN ENGINE (Legacy/Speed) ---
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Starting engine: UVICORN (HTTP/1.1) with {args.workers} workers")
    else:
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Starting engine: HYPERCORN (HTTP/2 Support) with {args.workers} workers")
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
            uvicorn.run( # pyright: ignore[reportPossiblyUnboundVariable]
                "mop:app",
                host=args.host,
                port=args.port,
                loop=loop_impl,
                ssl_keyfile=ssl_key if args.ssl else None,
                ssl_certfile=ssl_cert if args.ssl else None,
                workers=args.workers,
            ) 
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
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Shutting down IPC Manager...")
        manager.shutdown()
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Shutting plugins...", flush=True)
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
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Shutting down terminal sessions...")
        for session in sessions.values():
            term = cast(hints.Terminal,session["tty"])
            term.close()
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Terminal session pid:{term.pid} closed.")
                
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Server shutdown complete.")
