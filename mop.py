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
from typing import Literal, cast, BinaryIO, TextIO, Callable, TYPE_CHECKING, Optional
import warnings
from contextlib import asynccontextmanager
import signal

def is_frozen():
    return getattr(sys, 'frozen', False) or bool(getattr(sys, '_MEIPASS', []))

if __name__ == "__main__":
    print("[INFO] Python version: " + sys.version)
    print("[INFO] Is frozen: " + str(is_frozen()))

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
            ["pip", "check"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError("pip is not available in this environment")

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
    
    if not Path("./moppy/pickles/pickle.jpeg").exists():
        print("[CRITICAL] pickle.jpeg is missing. attempting to boot without it. May fail with a extremely high chance")
        time.sleep(0.5)
        print(f"[CRITICAL] FAILED TO BOOT. STATUS CODE: {r"\xff\xfe\x00\x00C\x00\x00\x00O\x00\x00\x00M\x00\x00\x00P\x00\x00\x00L\x00\x00\x00E\x00\x00\x00T\x00\x00\x00E\x00\x00\x00 \x00\x00\x00F\x00\x00\x00A\x00\x00\x00I\x00\x00\x00L\x00\x00\x00U\x00\x00\x00R\x00\x00\x00E\x00\x00\x00'"}")
        time.sleep(0.5)
        print("ok jokes over. time to boot")
        
    required_packages = [
        "fastapi",
        "uvicorn",
        "psutil",
        "brotli_asgi",
        "slowapi",
        "colorama",
        "brotlicffi",
        "aiohttp",
        "base91",
        "aiofiles",
    ]
    
    if sys.platform != "win32":
        required_packages.append("uvloop")

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
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, PlainTextResponse, StreamingResponse, Response, FileResponse # pyright: ignore[reportMissingImports]  # noqa: E402, F401
import uvicorn  # pyright: ignore[reportMissingImports] # noqa: E402
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

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", type=int, default=8000, help="Sets the port for MOP to bind to")
parser.add_argument("--host", type=str, default="127.0.0.1", help="Sets the interface for MOP to bind to") # arg parser is weird and wont let me use -h
parser.add_argument("-c", "--cmd", type=str, default="echo Hello World!", required=True, help="The command for MOP to wrap with either pty or pipes")
parser.add_argument("-r", "--rate-limit", default=False, action="store_true", help="Enables rate limits for possible abusive endpoints (/mop/write, /mop/init, etc.)")
parser.add_argument("--cwd", default=os.getcwd(), type=str, help="Sets the CWD for the sessions to run in")
parser.add_argument("--ssl", default=False, action="store_true", help="Enables SSL")
parser.add_argument("-w", "--workers", default=1, type=int, help="Sets the amount of FastAPI workers to spawn")
parser.add_argument("--force-port", default=False, action="store_true", help="Disables interactive prompts when another process is binded to the port FastAPI wants to use and kills the process using the port without warning")
parser.add_argument("--no-pub-process", default=False, action="store_true", help="Prevents automatic creation of a public session")
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

    used_port = get_pid_by_port(args.port)
    try:
        ps_port = psutil.Process(used_port)
        ps_PPID = psutil.Process(ps_port.ppid())
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        used_port = None
        return
    is_killed = False 
    if port and not args.force_port:
        print(f"{Fore.RED}ERROR{Fore.RESET}:     Port {args.port} is already in use by PID {used_port}.")
        print(f"{Fore.RED}ERROR{Fore.RESET}:     Process name: {ps_port.name()}")
        print(f"{Fore.RED}ERROR{Fore.RESET}:     Process status: {ps_port.status()}")
        print(f"{Fore.RED}ERROR{Fore.RESET}:     Process PPID: {ps_PPID.pid}")
        print(f"{Fore.RED}ERROR{Fore.RESET}:     Process PPID name: {ps_PPID.name()}")
        print(f"{Fore.RED}ERROR{Fore.RESET}:     Process PPID status: {ps_PPID.status()}")
        kill = input(f"{Fore.RED}ERROR{Fore.RESET}:     Do you want to kill the process? (y/n): ")
        if kill.lower() == "y":
            try:
                ps_port.terminate()
                print(f"{Fore.GREEN}INFO{Fore.RESET}:     Attempted to kill process. (SIGTERM)")
                ps_port.wait(timeout=3)
            except psutil.NoSuchProcess:
                print(f"{Fore.RED}ERROR{Fore.RESET}:     Failed to kill process.")
                sys.exit(1)
            except psutil.TimeoutExpired:
                print(f"{Fore.YELLOW}WARNING{Fore.RESET}:     Process did not terminate in time. Attempting to kill it with SIGKILL.")
                try:
                    ps_port.kill()
                except psutil.NoSuchProcess:
                    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Successfully killed process. (Process died after timeout)")
                    is_killed = True 
        is_not_killed = get_pid_by_port(args.port)
        if is_not_killed:
            print(f"{Fore.RED}ERROR{Fore.RESET}:     Failed to kill process.")
            sys.exit(1)
        elif not is_killed: # Confusing logic, i know
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Successfully killed process.")
    elif used_port and args.force_port:
        print(f"{Fore.YELLOW}WARNING{Fore.RESET}:     Port {args.port} is already in use by PID {used_port}. Forcing...")
        try:
            ps_port.terminate()
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Attempted to kill process. (SIGTERM)")
            ps_port.wait(timeout=3)
        except psutil.NoSuchProcess:
            print(f"{Fore.RED}ERROR{Fore.RESET}:     Failed to kill process.")
            sys.exit(1)
        except psutil.TimeoutExpired:
            print(f"{Fore.YELLOW}WARNING{Fore.RESET}:     Process did not terminate in time. Attempting to kill it with SIGKILL.")
            try:
                ps_port.kill()
                ps_port.wait(timeout=3)
            except psutil.NoSuchProcess:
                print(f"{Fore.GREEN}INFO{Fore.RESET}:     Successfully killed process. (Process died after timeout)")
                is_killed = True 
            except psutil.TimeoutExpired:
                print(f"{Fore.RED}ERROR{Fore.RESET}:     Failed to kill process.")
                sys.exit(1)
        is_not_killed = get_pid_by_port(args.port)
        if is_not_killed:
            print(f"{Fore.RED}ERROR{Fore.RESET}:     Failed to kill process.")
            sys.exit(1)
        elif not is_killed: # Confusing logic, i know
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Successfully killed process.")
            
if __name__ == "__main__":
    global core_plugins
    core_plugins = {}        
    f: TextIO # pyright: ignore[reportRedeclaration]
    with open("moppy/plugins/manifest.json", "r") as f:
        try:
            manifest = json.load(f)
        except json.JSONDecodeError:
            print(f"{Fore.RED}ERROR{Fore.RESET}:     Invalid plugin manifest!")
            sys.exit(1)
        except FileNotFoundError:
            print(f"{Fore.RED}ERROR{Fore.RESET}:     Plugin manifest not found!")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}ERROR{Fore.RESET}:     Failed to load plugin manifest: {e}")
            sys.exit(1)

    for name, plugin in manifest.items():
        if plugin.get("core", False):
            core_plugins[name] = plugin
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Found core plugin: {name}")
        else:
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Skipping non-core plugin: {name}")
    
    for name, plugin in core_plugins.items():
        missing = missing_deps(plugin.get("dependencies", []))
        if missing:
            for dep in missing:
                print(f"{Fore.RED}ERROR{Fore.RESET}:     Missing dependency: {dep}, Installing...")
                install_package(dep)
                check = pip_check_dependency(dep)
                if check["ok"]:
                    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Successfully installed dependency: {dep}")
                else:
                    print(f"{Fore.RED}ERROR{Fore.RESET}:     Failed to install dependency: {dep}, Issues: {check['issues']}")
                    sys.exit(1)
    
    safe_core_plugins = core_plugins.copy()
    for name, plugin in safe_core_plugins.items():
        runtime = plugin["runtime"]
        runtime = runtime.format(location=plugin["location"])
        current_cwd = os.getcwd()
        mop_cwd = os.path.join(current_cwd, "moppy")
        
        steal_port(plugin["port"])
        
        cmd = shlex.split(runtime)
        if "ssl" in plugin["supports"]:
            cmd.append("--ssl-certfile")
            cmd.append("./certs/cert.pem")
            cmd.append("--ssl-keyfile")
            cmd.append("./certs/key.pem")
        core_plugins["name"]["handle"] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=mop_cwd)
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Starting core plugin:", name + f" at port {plugin['port']}" if plugin["port"] else "")
        
        time.sleep(0.5)
        if core_plugins[name]["handle"].poll() is None:
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     {name} is running!")
        else:
            print(f"{Fore.RED}ERROR{Fore.RESET}:     {name} failed to start!")
            sys.exit(1)
            
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     All core plugins are running!")
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Loading required scripts...")
    
    scripts = Path("moppy/scripts").glob("*.py")
    
    for script in scripts:
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Loading script: {script}")
        handle = subprocess.Popen(["python", str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while handle.poll() is None:
            time.sleep(0.5)
        if handle.poll() != 0:
            print(f"{Fore.RED}ERROR{Fore.RESET}:     Failed to load script: {script}")
            sys.exit(1)
        else:
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Loaded script: {script}")

def is_uvicorn():
    try:
        parent_process = psutil.Process(os.getppid())
        if "uvicorn" in parent_process.name().lower():
            return True
        
        for arg in parent_process.cmdline():
            if "uvicorn" in arg.lower():
                return True
    except psutil.NoSuchProcess:
        pass
    return False

async def plugin_call(name, method="GET", content=None, path=""):
    global core_plugins
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
        # TODO: Fix this before 3.16
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    else:
        print(f"{Fore.YELLOW}WARNING{Fore.RESET}:     You are using a python version that has deprecated the WindowsSelectorEventLoopPolicy. This may cause issues. Please use 3.13.2 or lower.")
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy()) # pyright: ignore[reportAttributeAccessIssue] Stub doesnt have it yet
    
if sys.platform == "win32":
    import winpty # pyright: ignore[reportMissingImports]
else:
    import termios
    import pty as unixpty
    from moppy.hints import dummy_winpty as winpty 
    
env = os.environ.copy()

env.update({
    "PYTHONUNBUFFERED": "1",
    "PYTHONIOENCODING": "utf-8",
    "TERM": "xterm",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
})

sessions: dict[str, dict] = {}

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
pem_count = 0

for i in Path("./moppy/certs/").glob("*.pem"):
    pem_count += 1

is_ssl_certs_exists = pem_count >= 1

if args.ssl and not is_ssl_certs_exists:
    print(f"{Fore.RED}ERROR{Fore.RESET}:     .pem or .key file missing in /moppy/certs")
    prompt = input(f"{Fore.YELLOW}WARNING{Fore.RESET}:     Generate new SSL certificates? (y/n): ")
    if prompt.lower() != "y":
        print(f"{Fore.YELLOW}INFO{Fore.RESET}:     Exiting... Remove --ssl to disable SSL.")
        sys.exit(1)
    os.system(sys.executable + " ./moppy/ssl_certs.py")

global app

def create_app(command: list[str]):
    app = FastAPI()
    app.state.command = command
    return app

app: FastAPI = create_app(command)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start
    yield
    # End
    for name, plugin in core_plugins.items():
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Terminating plugin {name}")
        handle: subprocess.Popen = cast(subprocess.Popen, plugin["handle"])
        handle.terminate()
        start = time.time()
        while handle.poll() is None:
            if time.time() - start > 5:
                # Escalate: force kill
                print(f"{Fore.RED}WARNING{Fore.RESET}:     Plugin {name} is unresponsive. Killing.")
                handle.kill()
                break
            time.sleep(0.1)  # small sleep to avoid busy-waiting
        
        handle.wait()
        
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Plugin {name} terminated")
        

app.state.start_time = time.monotonic()
app.state.pepper =  b""

try:
    f_pepper: BinaryIO 
    with open("moppy/pepper", "rb") as f_pepper:
        f_pepper = cast(BinaryIO, f_pepper)
        app.state.pepper = bytes(base91.decode(f_pepper.read().split("🌶️".encode("utf-8"))[0]))
    
    if sys.platform != "win32":
        os.chmod("moppy/pepper", 0o600)
except FileNotFoundError:
    # Salt isnt found/generated yet
    app.state.pepper = secrets.token_bytes(32)
    f_pepper2: BinaryIO
    with open("moppy/pepper", "wb") as f_pepper2:
        f_pepper2 = cast(BinaryIO, f_pepper2)
        f_pepper2.write(base91.encode(app.state.pepper).encode("utf-8") + "🌶️".encode("utf-8"))
        
    if sys.platform != "win32":
        os.chmod("moppy/pepper", 0o600)
        
def big_hash(s) -> str:
    b = s if isinstance(s, bytes) else s.encode("utf-8")
    return hashlib.sha512(app.state.pepper + b).hexdigest()

# everything and everybody says that this is bad and shouldnt be used. but then why is it working tho
def etag_response(func):
    async def wrapper(request: Request):
        # Call the original endpoint
        response = await func(request)

        # Only for JSONResponse or HTMLResponse
        if isinstance(response, (JSONResponse, HTMLResponse)):
            body_bytes = response.body
            if not body_bytes:  # ensure bytes
                body_bytes = response.body.encode() if isinstance(response.body, str) else b""
            
            etag = hashlib.md5(body_bytes).hexdigest()
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


async def write(data: str, key: str):
    if key not in sessions:
        return {"status": "MOP transaction not started", "code": 1}, 428

    term = sessions[key]["tty"]  # Terminal object

    # Optional: check if Unix subprocess is already terminated
    if sys.platform != "win32" and term.proc.returncode is not None:
        return {"status": "Subprocess already terminated", "code": 2}, 410

    try:
        # Write to the terminal asynchronously
        if sys.platform == "win32":
            await term.write(data + "\r\n")
        else:
            await term.write(data + "\n")  # append newline for REPLs
    except (OSError, RuntimeError, BrokenPipeError) as e:
        return {"status": f"Failed to write to terminal: {e}", "code": 3}, 500
    except Exception as e:
        return {"status": f"Unexpected error: {e}", "code": 4}, 500

    return {"status": "Wrote data", "code": 0}, 200

async def read_stdout(key: str):
    # Just for websocket's sake
    data = await sessions[key]["buffer"].get("stdout", "")
    if len(data) == 0:
        return ""
    
    return data[len(data) - 1]

class Terminal:
    def __init__(self, proc: Optional[asyncio.subprocess.Process] = None, master_fd: Optional[int]=None, pty_obj: Optional[winpty.PTY]=None, use_pipes: bool = False):
        self.use_pipes: bool = use_pipes
        
        if self.use_pipes:
            self.proc: asyncio.subprocess.Process = cast(asyncio.subprocess.Process, proc) # type: ignore[no-redef]
        
        if sys.platform != "win32":
            self.master_fd: int = cast(int, master_fd)
            self.pty = None 
            self.proc: asyncio.subprocess.Process = cast(asyncio.subprocess.Process, proc) # type: ignore[no-redef]
        else:
            self.master_fd = None
            self.pty: winpty.PTY = cast(winpty.PTY, pty_obj)
            self.proc = None # pyright: ignore[reportAttributeAccessIssue] # type: ignore[no-redef]

    async def read(self, n=1024) -> dict[str, str]:
        loop = asyncio.get_running_loop()
        if self.use_pipes:
            stdout_obj = cast(asyncio.StreamReader, self.proc.stdout)
            stderr_obj = cast(asyncio.StreamReader, self.proc.stderr)
            stdout = await stdout_obj.read(n)
            stderr = await stderr_obj.read(n)
            
            return {"stdout": stdout.decode("utf-8"), "stderr": stderr.decode("utf-8")}
        if sys.platform == "win32":
            data = await loop.run_in_executor(None, self.pty.read)
            return {"stdout": data, "stderr": ""}
        else:
            data = await loop.run_in_executor(None, os.read, self.master_fd, n)
            return {"stdout": data.decode("utf-8"), "stderr": ""}
            
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
            
            await loop.run_in_executor(
                None, os.killpg, os.getpgid(self.proc.pid), unix_sig
            )
            
            os.close(self.master_fd)
            return


        if sig == utils.Signal.TERMINATE:
            self.proc.terminate()
        elif sig == utils.Signal.KILL:
            self.proc.kill()
        elif sig == utils.Signal.INTERRUPT:
            os.kill(self.proc.pid, signal.CTRL_C_EVENT) # Windows here
        

    async def write(self, data: str) -> None:
        loop = asyncio.get_running_loop()
        if self.proc is None:
            return
        
        if self.use_pipes:
            stdin_obj = cast(asyncio.StreamWriter, self.proc.stdin)
            stdin_obj.write(data.encode())
            await stdin_obj.drain()
            return
        if sys.platform == "win32":
            if self.pty is None:
                return
            await loop.run_in_executor(None, self.pty.write, data)
        else:
            if self.master_fd is None:
                return
            await loop.run_in_executor(None, os.write, self.master_fd, data.encode())
            
    @property
    def is_pipe(self) -> bool:
        return self.use_pipes
    
    @property
    def pid(self) -> int:
        if self.proc is None:
            return -1
        return self.proc.pid

async def spawn_tty(command: list[str], disable_echo=True) -> Terminal:
    new_cwd = Path(args.cwd).expanduser().resolve().absolute()
    if sys.platform == "win32":
        pty_obj = winpty.PTY(cols=80, rows=24)
        env_str = "\0".join(f"{k}={v}" for k, v in env.items()) + "\0"
        pty_obj.spawn(" ".join(command), env=env_str, cwd=str(new_cwd))
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
            preexec_fn=os.setsid
        )
        
        if disable_echo:
            attrs = termios.tcgetattr(slave_fd)
            attrs[3] = attrs[3] & ~(termios.ECHO | termios.ECHONL)  # disable echo
            termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
        
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


@app.post("/mop/init")
@limiter.limit("2/minute")
async def init(request: Request):
    command = app.state.command
    key = secrets.token_hex(64)
    hashed_key = big_hash(key)
    data = await request.json()
    echo = data.get("echo", False)
    attic = data.get("attic", False)
    use_pipe = data.get("use_pipe", False)
    
    if request.client is None:
        return JSONResponse({"status": "request.client is None", "comment": "Youre just as confused as i am. Blame Pylance", "code": 1}, status_code=500)
    
    if not use_pipe:
        process_handle = await spawn_tty(command, not echo)
    else:
        process_handle = await spawn_pipe(command)
    
    
    async def OUT_reader(default_key) -> None:
        buffers: dict[str, list[str]] = sessions[default_key]["buffers"]
        tty: Terminal = sessions[default_key]["tty"]  # should store Terminal object
            
        ANSI_CONTROL_RE: re.Pattern = re.compile(
            r'\x1b(?:'              # ESC
                r'(?!\[[0-9;]*m)'   # negative lookahead: skip SGR sequences
                r'\[[?0-9;]*[A-Za-z]'  # CSI sequences
                r'|[@-Z\\-_]'       # non-CSI sequences
            r')'
        )

        while True:
            try:
                data: dict[str, str] = await tty.read()
                if not data:
                    await asyncio.sleep(0.01)
                    continue
                
                if not isinstance(data, dict):
                    await asyncio.sleep(0.01)
                    continue
        
                stdout: str | bytes = data.get("stdout", "[ERROR reading stdout]")
                stderr: str | bytes = data.get("stderr", "[ERROR reading stderr]")
                
                if isinstance(stdout, bytes):
                    stdout = stdout.decode("utf-8")
                if isinstance(stderr, bytes):
                    stderr = stderr.decode("utf-8")
                    
                if not use_pipe:
                    stdout = ANSI_CONTROL_RE.sub('', stdout)
                    stderr = ANSI_CONTROL_RE.sub('', stderr)
                # Decode and append each character chunk            
                buffers["stdout"].append(stdout)
                buffers["stderr"].append(stderr)
            except Exception as e:
                buffers["stdout"].append(f"[ERROR reading stdout: {e}]")
                break
            
    async def IN_pub_writer():
        while True:
            data = await sessions[pub_key]["queue"].get()
            try:
                await write(data, pub_key)
            except Exception as e:
                logging.error(f"[ERROR writing stdin: {e}]")
            finally:
                sessions[pub_key]["queue"].task_done()
    
    sessions[hashed_key] = {"tty": process_handle, "command": command, "buffers": {"stdout": [], "stderr": []}, "tags": [], "mode": "pty" if use_pipe else "pipe"}
    sessions[hashed_key]["task_out"] = asyncio.create_task(OUT_reader(default_key=hashed_key))
    if pub_key not in sessions and not args.no_pub_process:
        pub_process_handle: Terminal = await spawn_tty(command)
        sessions[pub_key] = {"tty": pub_process_handle, "command": command, "buffer": [], "queue": asyncio.Queue(), "tags": ["public"], "mode": "pty"}
        sessions[pub_key]["task_out"] = asyncio.create_task(OUT_reader(default_key=pub_key))
        sessions[pub_key]["task_in"] = asyncio.create_task(IN_pub_writer())
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
        response["attic"] = attic_out
        response["key"] = attic
        del sessions[hashed_key]
        sessions[attic] = {"tty": process_handle, "command": command, "buffers": {"stdout": [], "stderr": []}, "tags": ["attic"], "mode": "pty"}
        sessions[attic]["task_out"] = asyncio.create_task(OUT_reader(default_key=attic))
    return JSONResponse(response, status_code=200)

@app.post("/mop/validate")
@limiter.limit("10/minute")
async def validate(request: Request):
    data = await request.json()
    key: str = data.get("key", "")
    if key == pub_key:
        return JSONResponse({"status": "Public key", "code": 0}, status_code=200)
    if big_hash(key) not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1}, status_code=404)
    return JSONResponse({"status": "Key exists", "code": 0}, status_code=200)

@app.post("/mop/attic/tell")
@limiter.limit("5/minute")
async def tell_attic(request: Request):
    data = await request.json()
    key: str = data.get("key", "")
    info = data.get("info")
    hashed_key = big_hash(key)
    if key == pub_key:
        return JSONResponse({"status": "Cannot set tell process data for public key", "code": 1}, status_code=403)
    if hashed_key not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1}, status_code=404)
    
    out = utils.attic(hashed_key, sessions[hashed_key]["tty"].pid).tell(info)
    
    return JSONResponse({"attic_response": out, "code": 0}, status_code=200)

@app.post("/mop/cosmetics/get_tags")
async def get_tags(request: Request):
    data = await request.json()
    key: str = big_hash(data.get("key"))
    if key not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1}, status_code=404)
    
    return JSONResponse({"tags": sessions[key]["tags"]}, status_code=200)

@app.post("/mop/cosmetics/set_tags")
async def set_tags(request: Request):
    data = await request.json()
    
    key: str = big_hash(data.get("key", ""))
    if key not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1}, status_code=404)
    
    sessions[key]["tags"] = data.get("tags")
    return JSONResponse({"status": "Tags updated", "code": 0}, status_code=200)

@app.post("/mop/set_attic")
async def persist_session(request: Request):
    data = await request.json()
    key: str = data.get("key")
    hashed_key: str = big_hash(key)
    
    if key == pub_key:
        return JSONResponse({"status": "Cannot set attic flag for public key", "code": 1}, status_code=403)
    
    if hashed_key not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1}, status_code=404)
    
    sessions[hashed_key]["attic"] = True
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Attic flag set for {hashed_key[:6]}")
    return JSONResponse({"status": "Attic flag set", "code": 0}, status_code=200)

@app.post("/mop/power/stream/read")
async def sse_read(request: Request):
    # 1. Auth Check (Crucial for Power endpoints)
    data = await request.json()
    key: str = big_hash(data.get("key", ""))
    if key not in sessions:
        return JSONResponse({"status": "Invalid Key"}, status_code=428)

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
    if big_hash(key) not in sessions:
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
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     {client} - Session {big_hash(key)[:6]} connected")
    
    try:
        async def send_to_client():
            while True:
                tty = sessions[big_hash(key)]["tty"]
                data = await tty.read()
                if data:
                    await websocket.send_text(data)
                await asyncio.sleep(0.1)
        async def receive_from_client():
            last_msg_time = time.time()
            msg_count = 0
            while True:
                data = await websocket.receive_text()
                current_time = time.time()
                
                if current_time - last_msg_time < 1.0:
                    msg_count += 1
                else:
                    msg_count = 0
                    last_msg_time = current_time
                    
                if msg_count > 50: # Limit to 50 messages per second
                    await asyncio.sleep(0.5) # Force the client to wait (Backpressure)
                    continue
                
                if is_pub_key:
                    sessions[pub_key]["queue"].put_nowait(data)
                else:
                    await write(data, big_hash(key))
                    
        await asyncio.gather(send_to_client(), receive_from_client())
    except WebSocketDisconnect:
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     {client} - Session {big_hash(key)[:6]} disconnected")
    finally:
        term = sessions[key]["tty"]  # Terminal object

        try:
            # Cancel the readers first
            sessions[key]["task_out"].cancel()

        except Exception:
            pass

        # Kill/close the terminal subprocess
        if sys.platform == "win32":
            try:
                term.pty.kill()  # pywinpty has a .kill() method
            except Exception:
                pass
        else:
            try:
                term.proc.terminate()
                await term.proc.wait()
                os.close(term.master_fd)
            except Exception:
                pass

        # Remove from sessions
        del sessions[big_hash(key)]

        # Clean up public key session if no other sessions remain
        if len(sessions) < 2 and pub_key in sessions:
            try:
                sessions[pub_key]["task_out"].cancel()
                sessions[pub_key]["queue"].put_nowait(None)
                sessions[pub_key]["task_in"].cancel()
            except Exception:
                pass
            pub_term = sessions[pub_key]["tty"]
            if sys.platform == "win32":
                try:
                    pub_term.pty.kill()
                except Exception:
                    pass
            else:
                try:
                    pub_term.proc.terminate()
                    await pub_term.proc.wait()
                    os.close(pub_term.master_fd)
                except Exception:
                    pass
            del sessions[pub_key]

    return JSONResponse({"status": "Session ended", "code": 0})
    
@app.post("/mop/signal")
async def signalButRequest(request: Request):
    data = await request.json()
    key: str = data.get("key")
    signal: Literal["INTERRUPT", "TERMINATE", "KILL"] = data.get("signal")
    if signal not in ("INTERRUPT", "TERMINATE", "KILL"):
        return JSONResponse({"status": "Invalid signal", "code": 1})
        
    if key == pub_key:
        return JSONResponse({"status": "Cannot send any signal to public key", "code": 1}, 403)
            
    hashed_key: str = big_hash(key)
    if hashed_key not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1})
        
    signal_map = {
        "INTERRUPT": utils.Signal.INTERRUPT,
        "TERMINATE": utils.Signal.TERMINATE,
        "KILL": utils.Signal.KILL
    }
    
    try:
        await sessions[hashed_key]["tty"].send_signal(signal_map[signal])
        del sessions[hashed_key]
        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Sent signal {signal} to session {hashed_key[:6]}")
        if len(sessions) < 2:
            await sessions[pub_key]["tty"].send_signal(utils.Signal.TERMINATE)
            del sessions[pub_key]
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Killed public session {pub_key[:6]} due to no other sessions remaining")
        return JSONResponse({"status": "Signal sent", "code": 0})
    except Exception:
        return JSONResponse({"status": "Failed to send signal", "code": 1})
        
    


    
@app.post("/mop/end")
async def end(request: Request):
    data = await request.json()
    key: str = data.get("key")
    hashed_key: str = big_hash(key)
    failed_to_store: str = ""
    if hashed_key not in sessions and key != pub_key:
        return JSONResponse({"status": "Invalid key", "code": 1})

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
            term.send_signal(utils.Signal.KILL)
        except Exception:
            pass
    elif sys.platform != "win32" and not term.is_pipe:
        try:
            await term.send_signal(utils.Signal.TERMINATE)
            await term.proc.wait()
            os.close(term.master_fd)
        except Exception:
            pass
    
    if term.is_pipe:
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
            sessions[pub_key]["queue"].put_nowait(None)
            sessions[pub_key]["task_in"].cancel()
        except Exception:
            pass
        pub_term = sessions[pub_key]["tty"]
        if sys.platform == "win32":
            try:
                pub_term.send_signal(utils.Signal.KILL)
            except Exception:
                pass
        else:
            try:
                pub_term.send_signal(utils.Signal.TERMINATE)
                os.close(pub_term.master_fd)
            except Exception:
                pass
        del sessions[pub_key]
    
    client = f"{request.client.host}:{request.client.port}"
    print(f"{Fore.GREEN}INFO{Fore.RESET}:    {client} - Key {hashed_key[:6]} Session ended")
    return JSONResponse({"status": f"Session ended{f" and failed to store to attic due to {str(failed_to_store)}" if failed_to_store else ""}", "code": 0})

@app.post("/mop/write")
@limiter.limit("60/minute")
async def write_stdin(request: Request):
    data = await request.json()
    key: str = data.get("key")
    hashed_key: str = big_hash(key)
    stdin_data: str = data.get("stdin", "")
        
    if key == pub_key:
        sessions[pub_key]["queue"].put_nowait(stdin_data)
        return JSONResponse({"status": "Put into queue", "position": sessions[pub_key]["queue"].qsize(), "code": 0}, status_code=200)
    
    if hashed_key not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1}, status_code=400)

    # Call the new write
    out = await write(stdin_data, hashed_key)
    return JSONResponse(out[0], status_code=out[1])

@app.post("/mop/read")
async def read(request: Request):
    data = await request.json()
    key: str = big_hash(data.get("key"))
    if key not in sessions:
        return JSONResponse({"status": "Invalid key", "code": 1})
    
    out: dict[str, str] = {"stdout": sessions[key]["buffers"].get("stdout", ""), "stderr": sessions[key]["buffers"].get("stderr", ""), }
    return JSONResponse({"stdout": out["stdout"], "stderr": out.get("stderr", ""), "code": 0, "output_hash": big_hash(json.dumps(out, sort_keys=True))}, status_code=200)

@app.post("/mop/ping")
async def ping(request: Request):
    data = await request.json()
    key: str = big_hash(data.get("key"))
    if not data.get("key"):
        return JSONResponse({"status": "Missing key", "code": 1}, status_code=400)
    
    if key not in sessions:
        return JSONResponse({"status": "Session not found", "code": 2}, status_code=404)
    
    term = sessions[key]["tty"]
    
    # Check if process is alive
    if sys.platform == "win32":
        is_alive = term.pty.isalive()
    else:
        is_alive = term.proc.returncode is None
    
    if is_alive:
        return JSONResponse({"status": "OK", "code": 0}, status_code=200)
    else:
        return JSONResponse({"status": "Process terminated", "code": 3}, status_code=410)

@app.get("/mop/process")
async def process():
    if pub_key not in sessions:
        return JSONResponse(
            {
                "status": "No process is running.", 
                "server_id": server_id,
                "command": list(app.state.command),
                "uptime": f"{int(time.monotonic() - app.state.start_time)}",
                "version": "1.0.0",
                "code": 1
            }, status_code=428)
    data = {
        "command": list(app.state.command),
        "server_id": server_id,
        "sessions": len(sessions.keys()),
        "pub_key": pub_key,
        "pending_writes": sessions[pub_key]["queue"].qsize(),
        "uptime": f"{int(time.monotonic() - app.state.start_time)}",
        "version": "1.0.0",
        "code": 0
    }
    return JSONResponse(data, status_code=200)

@app.get("/")
async def root(request: Request):
    if request.headers.get("Accept", "text/plain") == "application/json":
        return JSONResponse({"status": "use /mop/", "comment": "wrong url bud. its /mop","code": 0}, status_code=400)
    
    return PlainTextResponse("I think you may have gotten the wrong url buddy.\nIf you are looking for MAT (webui) then change your port to 8080.\nIf you are looking for the api then its /mop")
    
@app.get("/{path:path}")
async def external_endpoint_get(request: Request, path: str):
    try:
        response: dict = await utils.external_endpoint(path, "GET").call("GET")
    except NotImplementedError as e:
        if request.headers.get("Accept", "text/plain") == "application/json":
            return JSONResponse({"status": f"External endpoint at {path} is not implemented"}, status_code=404)
        return PlainTextResponse("404 Not Found" + f" {str(e)}", status_code=404)
        
    content = response.get("content", "")
    
    status_code = response.get("status", 200) if not content == "" else response.get("status", 204)
    
    
    header = response.get("headers", {})
    
    return Response(content, status_code=status_code, headers=header, media_type=response.get("media_type", "application/octet-stream"))

    
def get_certs():
    cert_dir = Path("./mop/certs")
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
            print(f"{Fore.YELLOW}WARNING{Fore.RESET}:     .pem or .key file missing in /mop/certs")
        
        
    
    for file in cert_dir.glob("*.pem"):
        content = file.read_text()
        if "PRIVATE KEY" in content:
            ssl_key = str(file.absolute())
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Found KEY")
        elif "CERTIFICATE" in content:
            ssl_cert = str(file.absolute())
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Found CERTIFICATE")
        
    if not ssl_cert or not ssl_key:
        print(f"{Fore.YELLOW}WARNING{Fore.RESET}:     .pem or .key file missing in /mop/certs")
    return ssl_cert, ssl_key

if __name__ == "__main__" and not is_uvicorn():
    if not Path(args.cwd).expanduser().absolute().exists():
        print(f"{Fore.RED}ERROR{Fore.RESET}:     cwd directory does not exist: {args.cwd}")
        sys.exit(1)
        
    if not Path(args.cwd).expanduser().absolute().is_dir():
        print(f"{Fore.RED}ERROR{Fore.RESET}:     cwd is not a directory: {args.cwd}")
        sys.exit(1)
        
    
    ssl_cert, ssl_key = None, None
    if args.ssl:
        ssl_cert, ssl_key = get_certs()
    else:
        print(f"{Fore.YELLOW}WARNING{Fore.RESET}:     You are not using SSL. This is not recommended for production use. Use --ssl to enable SSL.")
            
    if sys.platform == "win32":
        print(f"{Fore.YELLOW}WARNING{Fore.RESET}:     Windows is not very well supported. Use Linux or WSL. Echo cannot be disabled on Windows.")
        
    loop_impl: Literal["uvloop", "asyncio"] = "uvloop" if sys.platform != "win32" else "asyncio"
    
    steal_port(args.port)
    
    config: uvicorn.Config = uvicorn.Config(
        "mop:app",
        host=args.host,
        port=args.port,
        loop=loop_impl,
        ssl_keyfile=ssl_key if args.ssl else None,
        ssl_certfile=ssl_cert if args.ssl else None,
        workers=args.workers,
        
    )
    server: uvicorn.Server = uvicorn.Server(config=config)
    try:
        if "mat" in manifest.keys(): # pyright: ignore[reportPossiblyUnboundVariable]
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Mat is running on http{'s' if args.ssl else ''}://{args.host}:8080")
        server.run()
    except KeyboardInterrupt:
        print(f"{Fore.RED}ERROR{Fore.RESET}:     KeyboardInterrupt detected. Exiting...")
    except Exception as e:
        print(f"{Fore.RED}ERROR{Fore.RESET}:     {e}")