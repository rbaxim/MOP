"""
Just for the type checker to shut up
"""
from __future__ import annotations
from typing import Protocol, Literal, TypedDict, Optional, Any, Union, TypeAlias, TYPE_CHECKING
import asyncio
from enum import Enum, auto
import subprocess
if TYPE_CHECKING:
    import moppy.utils as utils
    import mop


class Signal(Enum):
    INTERRUPT = auto()
    TERMINATE = auto()
    KILL = auto()
    
# class ByteLimitedLog(Protocol):
#     def __init__(self, max_bytes=1048576, max_lines=9000) -> None: ...
#     def append(self, line_str) -> None: ...
#     def get_full_buffer(self) -> bytes: ...
#     def buffer(self) -> list[str]: ...

class TextStream(Protocol):
    def write(self, s: str) -> int: ...
    def flush(self) -> None: ...
    def isatty(self) -> bool: ...

# class Terminal(Protocol):
#     def __init__(self, proc: Optional[asyncio.subprocess.Process] = None, master_fd: Optional[int]=None, pty_obj: Optional[Any]=None, use_pipes: bool = False) -> None: ...
#     async def read(self, n=1024, waivers: set = set()) -> dict[str, str]: ...
#     async def send_signal(self, sig: Signal) -> None: ...
#     async def write(self, data: str, timeout=5.0, waivers=set()) -> None: ...
#     def close(self) -> None: ...
#     @property
#     def is_pipe(self) -> bool: ...
#     @property
#     def pid(self) -> int: ...

class buffers_dict(TypedDict):
    stdout: utils.ByteLimitedLog
    stderr: utils.ByteLimitedLog

class PrivSession(TypedDict):
    tty: mop.Terminal
    command: list[str]
    buffers: buffers_dict
    tags: list
    mode: Literal["pty", "pipe"]
    waivers: set[Union[str, utils.Waiver]]
    task_out: asyncio.Task
    attic: Optional[bool]

class PubSession(TypedDict):
    tty: mop.Terminal
    command: list[str]
    buffers: buffers_dict
    tags: list
    mode: Literal["pty"]
    queue: asyncio.Queue[Any]
    task_out: asyncio.Task
    task_in: asyncio.Task
    
class Plugin(TypedDict):
    location: str
    acronym: Optional[str]
    dependencies: list
    runtime: str
    supports: list[Literal["ssl"]]
    core: bool
    enabled: bool
    port: Optional[int]
    role: Optional[str]
    handle: Optional[subprocess.Popen] # Not that this is optional. Just that it may not exist at certain points in time

Plugin_Manifest: TypeAlias = dict[str, Plugin]

Session_storage: TypeAlias = dict[str, Union[PrivSession, PubSession]]