# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 rbaxim
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for details.
import aiohttp # pyright: ignore[reportMissingImports]
import ssl
import aiofiles # pyright: ignore[reportMissingModuleSource]
import asyncio
from concurrent.futures import ThreadPoolExecutor
import psutil # pyright: ignore[reportMissingModuleSource]
import json
import shlex
from enum import Enum, auto
import sys
from collections import deque

class ByteLimitedLog:
    def __init__(self, max_bytes=1048576, max_lines=9000):
        self.lines = deque()
        self.max_bytes = max_bytes
        self.current_bytes = 0
        self.max_lines = max_lines

    def append(self, line_str):
        # We encode to utf-8 to get the actual byte weight
        line_bytes = line_str.encode('utf-8')
        line_len = len(line_bytes)

        # If a single line is bigger than the whole buffer, 
        # you might want to truncate it or handle it specially.
        if line_len > self.max_bytes:
            line_bytes = f"[TRUNCATED LINE OF LENGTH: {line_len}]\n".encode('utf-8')
            line_len = self.max_bytes

        # Add new line weight
        self.lines.append(line_bytes)
        self.current_bytes += line_len

        # Evict old lines until we are under the limit
        while self.current_bytes > self.max_bytes or len(self.lines) > self.max_lines:
            removed_line = self.lines.popleft()
            self.current_bytes -= len(removed_line)

    def get_full_buffer(self) -> bytes:
        return b"".join(self.lines)
    
    def buffer(self) -> list[bytes]:
        return list(self.lines)


session: aiohttp.ClientSession | None = None  # global

async def get_session():
    global session
    if session is None:
        timeout = aiohttp.ClientTimeout(total=10)
        session = aiohttp.ClientSession(timeout=timeout)
    return session

def make_ssl_context():
    try:
        ctx = ssl.create_default_context(cafile="./moppy/certs/cert.pem")  
    except Exception:
        # http, main server warns about this. so its usually safe in this case
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    return ctx

async def get_auth() -> tuple[str, str]:
    async with aiofiles.open("moppy/auth/private_key.pem", "r") as f:
        private_key = await f.read()

    async with aiofiles.open("moppy/auth/certificate.pem", "r") as f:
        certificate = await f.read()

    return private_key, certificate

async def fetch_backend(path: str, method="GET", body=None, headers=None, port=8000):
    ssl_context = make_ssl_context()
    urls = [
        ("https", f"https://localhost:{port}/{path}"),
        ("https", f"https://127.0.0.1:{port}/{path}"),
        ("http",  f"http://localhost:{port}/{path}"),
        ("http",  f"http://127.0.0.1:{port}/{path}"),
    ]

    last_error = None
    
    session = await get_session()

    for scheme, url in urls:
        try:
            async with session.request( # pyright: ignore[reportOptionalMemberAccess]
                method,
                url,
                data=body,
                headers=headers,
                ssl=ssl_context if scheme == "https" else False,
            ) as resp:
                content = await resp.read()
                return {
                    "status": resp.status,
                    "body": content,
                    "headers": resp.headers,
                }
        except (aiohttp.ClientConnectorError, ssl.SSLError) as e:
            last_error = e
            continue
    return {
        "status": 500,
        "body": f"Failed to fetch backend due to {last_error}".encode("utf-8"),
        "headers": {},
    }
    
def get_command_by_pid(pid):
    try:
        # Create a Process object
        p = psutil.Process(pid)
        
        # Get the command line as a list
        cmd_list = p.cmdline()
        
        # Join the list into a single string for readability
        full_command = " ".join(cmd_list)
        return full_command
        
    except psutil.NoSuchProcess:
        return "Process ID not found."
    except psutil.AccessDenied:
        return "Permission denied (try running as sudo/admin)."
    
# This code is not so modular and you will need to add pieces of code here for modifications of core/not-core plugins
class attic():
    def __init__(self, key: str, pid: int):
        # Key is prehashed
        self.key = key
        self._content = {}
        self.pid = pid
        try:
            data = self._run_sync(fetch_backend(f"attic/{self.key}", port=9000))
            self._content = data["body"]
        except Exception:
            self._content = {}
        
    def _run_sync(self, coroutine):
        """Safely bridges async calls into the sync"""
        try:
            # Check if we are already inside a running event loop
            asyncio.get_running_loop()
            with ThreadPoolExecutor() as exec:
                return exec.submit(lambda: asyncio.run(coroutine)).result()
        except RuntimeError:
            # No loop running, we can start one
            return asyncio.run(coroutine)
    
    def __repr__(self):
        return f"attic({self.key})"
    async def set(self, value):
        path = "attic/store"
        await fetch_backend(path, method="POST", body={"key": self.key, "pid": self.pid, "program": get_command_by_pid(self.pid), "pickle": value}, port=9000)
        get_data = {
            "program": get_command_by_pid(self.pid),
            "pickle": value,
            "port": "Not Found"
        }
        self._content[self.key] = get_data
        
    async def get(self):
        return self._content
    
    async def reload(self):
        try:
            data = await fetch_backend("attic/retrieve", port=9000, method="POST", body={"key": self.key})
            self._content = data["body"]
        except Exception:
            self._content = {}
            
    def tell(self, info, key=None):
        if key:
            self._run_sync(fetch_backend("attic/proc/tell", port=9000, method="POST", body={"key": key, "info": info}))
        else:
            self._run_sync(fetch_backend("attic/proc/tell", port=9000, method="POST", body={"key": self.key,"info": info}))
        
    @property
    def content(self):
        return self._content

class external_endpoint():
    json_endpoints: dict[str, list[dict[str, str]]] = {}
    
    def __init__(self, path, method):
        self.path = path
        
        if external_endpoint.json_endpoints == {}:
            with open("./moppy/mop_custom_endpoints.json", "r") as f:
                external_endpoint.json_endpoints = json.loads(f.read())
        for endpoint in external_endpoint.json_endpoints["endpoints"]:
            if endpoint["path"].lstrip("/") == self.path.lstrip("/") and endpoint["method"].upper() == method.upper():
                self.name = endpoint["name"]
                self.method = endpoint["method"]
                self.runtime = endpoint["runtime"]
                return
        
        raise NotImplementedError(f"External endpoint {self.path} has not been implemented yet.")
    
    def __repr__(self):
        return f"external_endpoint({self.path})"
    
    async def call(self, arguments):
        endpoint = await asyncio.create_subprocess_exec(*shlex.split(f"{self.runtime} {arguments}"), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd="./moppy")
        
        stdout, stderr = await endpoint.communicate()
        
        formatted_request = json.loads(stdout.decode("utf-8"))
        
        return formatted_request
    
class Signal(Enum):
    INTERRUPT = auto()
    TERMINATE = auto()
    KILL = auto()

def preexec(slave_fd: int, disable_echo: bool) -> None:
    if sys.platform == "win32":
        raise NotImplementedError("preexec is not supported on Windows.")
    import os
    import fcntl
    import termios
    os.setsid()
    # Make slave controlling tty
    fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
    
    if disable_echo:
        attrs = termios.tcgetattr(slave_fd)
        attrs[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
    
    os.dup2(slave_fd, 0)
    os.dup2(slave_fd, 1)
    os.dup2(slave_fd, 2)
    os.close(slave_fd)