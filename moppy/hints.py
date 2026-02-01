"""
Just for the type checker to shut up
"""
from typing import Protocol, Literal, TypedDict, Optional, Any, Union
import asyncio
from enum import Enum, auto

class Signal(Enum):
    INTERRUPT = auto()
    TERMINATE = auto()
    KILL = auto()
    
class ByteLimitedLog:
    def __init__(self, max_bytes=1048576, max_lines=9000) -> None: ...
    def append(self, line_str) -> None: ...
    def get_full_buffer(self) -> bytes: return b""
    def buffer(self) -> list[str]: return [""]

class TextStream(Protocol):
    def write(self, s: str) -> int: ...
    def flush(self) -> None: ...
    def isatty(self) -> bool: ...

class Terminal(Protocol):
    def __init__(self, proc: Optional[asyncio.subprocess.Process] = None, master_fd: Optional[int]=None, pty_obj: Optional[Any]=None, use_pipes: bool = False) -> None: ...
    async def read(self, n=1024, waivers: set = set()) -> dict[str, str]: ...
    async def send_signal(self, sig: Signal) -> None: ...
    async def write(self, data: str, timeout=5.0, waivers=set()) -> None: ...
    def close(self) -> None: ...
    @property
    def is_pipe(self) -> bool: ...
    @property
    def pid(self) -> int: ...

class buffers(TypedDict):
    stdout: ByteLimitedLog
    stderr: ByteLimitedLog

class PrivSession(TypedDict):
    tty: Terminal
    command: list[str]
    buffer: buffers
    tags: list
    mode: Literal["pty", "pipe"]
    waivers: set[Union[str, Any]]
    task_out: asyncio.Task

class PubSession(TypedDict):
    tty: Terminal
    command: list[str]
    buffer: buffers
    tags: list
    mode: Literal["pty"]
    queue: asyncio.Queue
    task_out: asyncio.Task
    task_in: asyncio.Task