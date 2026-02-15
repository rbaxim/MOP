"""
Just for the type checker to shut up
"""
from __future__ import annotations
from typing import Protocol, Literal, TypedDict, Optional, Any, Union, TypeAlias, TYPE_CHECKING, cast, Annotated
import asyncio
from enum import Enum, auto
import subprocess
from pydantic import BaseModel, Field, model_validator, WithJsonSchema # type: ignore[attr-defined] # Mypy cli is stupid
import sys
if TYPE_CHECKING:
    import moppy.utils as utils
    if sys.platform == "win32":
        try:
            import ConPTYBridge.conpty as conpty # noqa: F401
        except ImportError:
            import winpty # pyright: ignore[reportMissingImports] # noqa: F401
    else:
        import fcntl # noqa: F401
        import pty as unixpty # noqa: F401
    
class Terminal: # Mypy. its just typing
    def __init__(self, proc: Optional[asyncio.subprocess.Process] = None, master_fd: Optional[int]=None, pty_obj: Optional[Union['winpty.PTY', "conpty.ConPTYInstance"]]=None, use_pipes: bool = False): ... # type: ignore[name-defined, valid-type]
        
    def _on_pty_readable(self): ...
            
    def _prime_pty(self): ...

    async def read(self, n=1024, waivers: set[Any] = set()) -> dict[str, str]: ... # type: ignore
        
    async def send_signal(self, sig: utils.Signal) -> None: ... # pyright: ignore[reportAttributeAccessIssue]
    
    async def _wait_writable(self, fd, timeout=5.0): ...
    
    async def write(self, data: str, timeout=5.0) -> None: ...
    
    def close(self) -> None: ...
    
    @property
    def is_pipe(self) -> bool: ... # type: ignore
    
    @property
    def pid(self) -> int: ... # type: ignore
    
    @property
    def proc(self) -> Union[asyncio.subprocess.Process, None]: ... # type: ignore
    
    @property
    def master_fd(self) -> int: ... # type: ignore
    
    @property
    def is_alive(self) -> bool: ... # type: ignore


class Signal(Enum):
    INTERRUPT = auto()
    TERMINATE = auto()
    KILL = auto()

class TextStream(Protocol):
    def write(self, s: str) -> int: ...
    def flush(self) -> None: ...
    def isatty(self) -> bool: ...

class buffers_dict(TypedDict):
    stdout: utils.ByteLimitedLog
    stderr: utils.ByteLimitedLog

class PrivSession(TypedDict):
    tty: Terminal # pyright: ignore[reportAttributeAccessIssue]
    command: list[str]
    buffers: buffers_dict
    tags: list
    mode: Literal["pty", "pipe"]
    waivers: set[Union[str, utils.Waiver]]
    task_out: asyncio.Task
    attic: Optional[bool]

class PubSession(TypedDict):
    tty: Terminal # pyright: ignore[reportAttributeAccessIssue]
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
    
responses_type: TypeAlias = dict[int | str, dict[str, Any]]
    
class models():
    class MopInit(BaseModel):
        echo: bool = Field(False, description="Decides whether MOP should allow the PTY to echo output")
        attic: Annotated[
        Union[str, bool, None],
        WithJsonSchema({
            "type": "string",
            "format": "key",
            "example": "<Attic marked session key>"
        })] = Field(None, description="Key for MOP to check inside of ATTIC.")
        use_pipe: bool = Field(False, description="Tells MOP to use Pipes instead of PTY")
        
        @model_validator(mode="before") # pyright: ignore[reportCallIssue]
        @classmethod
        def default_attic_false(cls, values):
            # Capture cases where 'attic' is missing, None, or an empty string
            val = values.get("attic")
            if val is None or val == "" or "attic" not in values:
                values["attic"] = False
            return values
        
    class MopAlias(BaseModel):
        key: str = Field(..., description="Key to alias")
        
    class MopValidate(BaseModel):
        key: str = Field(..., description="Key to validate")
        
    class MopAtticTell(BaseModel):
        key: str = Field(..., description="Key to tell process via ATTIC")
        info: str = Field(..., description="Information to tell process via ATTIC")
        
    class MopCosmeticsGet_tags(BaseModel):
        key: str = Field(..., description="Key to get tags")
        
    class MopCosmeticsSet_tags(BaseModel):
        key: str = Field(..., description="Key to set tags")
        tags: list = Field(..., description="Tags to set")
        
    class MopSet_attic(BaseModel):
        key: str = Field(..., description="Key to flag with ATTIC")
        
    class MopPowerStreamRead(BaseModel):
        key: str = Field(..., description="Key to get STDOUT stream from")
    
    class MopSignal(BaseModel):
        key: str = Field(..., description="Key to send signal to")
        signal: Literal["INTERRUPT", "TERMINATE", "KILL"] = Field(..., description="Signal to send")
    
    class MopEnd(BaseModel):
        key: str = Field(..., description="Session key to end")
    
    class MopWrite(BaseModel):
        key: str = Field(..., description="Key to write")
        stdin: str = Field(..., description="Data to write to stdin")
        newline: bool = Field(False, description="Add a OS-Specific newline if STREAM_STDIN waiver is enabled")
        
    class MopRead(BaseModel):
        key: str = Field(..., description="Key to read from")
        
    class MopWaiver(BaseModel):
        key: str = Field(..., description="Key to set waivers")
        waivers: dict = Field({}, description="Waivers to set")
        remove: list = Field([], description="Waivers to remove")
        
    class MopPing(BaseModel):
        key: str = Field(..., description="Key to ping")
        
        
class responses():
    status_code_list: dict[int, str] = {
        504: "Gateway Timeout",
        500: "Internal Server Error",
        429: "Too Many Requests",
        428: "Precondition Required",
        410: "Gone",
        404: "Not Found",
        403: "Forbidden",
        200: "Success",
        400: "Bad Request"
    }
    
    status_code_type: TypeAlias = Literal[504,500,429,428,410,404,403,400,200]
    
    @staticmethod
    def response_template(status_code: status_code_type=200, mime_type="application/json", example: Optional[Any]=None, multiple_examples=False) -> responses_type:
        if example is None:
            raise ValueError("Expected dict in example. Got None")
        
        if multiple_examples:
            fixed_example = {}
            for key, value in cast(dict, example.items()):
                fixed_example[key] = {"value": value}
            template: responses_type = {
                status_code: {
                    "description": responses.status_code_list[status_code],
                    "content": {
                        mime_type: {
                            "examples": fixed_example
                        }
                    }
                },
            }
        else:
            template: responses_type = { # type: ignore[no-redef]
                status_code: {
                    "description": responses.status_code_list[status_code],
                    "content": {
                        mime_type: {
                            "example": example
                        }
                    }
                },
            }

        return template
    
    @staticmethod
    def ratelimit(ratelimit) -> responses_type:
        return responses.response_template(429, mime_type="application/json", example={"detail": f"Rate limit exceeded: {ratelimit}"})
    
    @staticmethod
    def MopInit() -> responses_type:
        response: responses_type = {
            **responses.response_template(500, example={"Invalid Client": {"status": "request.client is None", "comment": "Youre just as confused as i am. Blame Pylance", "code": 1}, "Attic Error": {"status": "Error retrieving attic", "code": 1, "error": "<error message>"}}, multiple_examples=True),
            **responses.ratelimit("2 requests per 1 minute"),
            **responses.response_template(200, example={"status": "Session started", "code": 0, "key": "0504b284...", "public_key": "a0a0ba81..."}),
            **responses.response_template(400, example={"Pipe Not Supported": {"status": "Current terminal backend does not support pipes", "code": 1}, "PTY Not Supported": {"status": "Current terminal backend does not support pty. Call with use_pipe instead", "code": 1}}, multiple_examples=True)
        }
        return response
    
    @staticmethod
    def MopAlias() -> responses_type:
        response: responses_type = {
            **responses.ratelimit("1 requests per 1 minute"),
            **responses.response_template(404, example={"status": "Invalid key", "code": 1}),
            **responses.response_template(200, example={"Private Session": {"status": "Created Alias", "alias": "3b041453...", "code": 0}, "Public Session": {"status": "Created Alias", "alias": "Public", "Comment": "Save time by just using the alias 'Public' for the public session", "code": 0}}, multiple_examples=True),
        }
        return response
    
    @staticmethod
    def MopValidate() -> responses_type:
        response: responses_type = {
            **responses.response_template(404, example={"status": "Invalid key", "code": 1}),
            **responses.ratelimit("10 requests per 1 minute"),
            **responses.response_template(200, example={"Private Key": {"status": "Key exists", "code": 0}, "Public Key": {"status": "Public key", "code": 0}}, multiple_examples=True)
        }
        return response
    
    @staticmethod
    def MopAtticTell() -> responses_type:
        response: responses_type = {
            **responses.response_template(404, example={"status": "Invalid key", "code": 1}),
            **responses.ratelimit("5 requests per 1 minute"),
            **responses.response_template(200, example={"status": "Sucessfully got attic output","attic_response": "<attic_response>", "code": 0}),
            **responses.response_template(403, example={"status": "Cannot tell process data for public key", "code": 1}),
        }
        return response
    
    @staticmethod
    def MopCosmeticsGet_tags() -> responses_type:
        response: responses_type = {
            **responses.response_template(404, example={"status": "Invalid key", "code": 1}),
            **responses.response_template(200, example={"tags": ["Insert", "Tags", "Here"], "code": 0})
        }
        return response
    
    @staticmethod
    def MopCosmeticsSet_tags() -> responses_type:
        response: responses_type = {
            **responses.response_template(404, example={"status": "Invalid key", "code": 1}),
            **responses.response_template(200, example={"status": "Tags updated", "code": 0})
        }
        return response
    
    @staticmethod
    def MopSet_attic() -> responses_type:
        response: responses_type = {
            **responses.response_template(403, example={"status": "Cannot set attic flag for public key", "code": 1}),
            **responses.response_template(404, example={"status": "Invalid key", "code": 1}),
            **responses.response_template(200, example={"status": "Attic flag set", "code": 0})
        }
        return response
    
    @staticmethod
    def MopPowerStreamRead() -> responses_type:
        response: responses_type = {
            **responses.response_template(200, "text/event-stream", 'data: {"stdout": "hello there", "stderr": ""}\n\ndata: {"stdout": "ooh new data", "stderr": "uh oh. error :("}\n\n: heartbeat\n\n{"stdout": "hahaha heart beat", "stderr": ""}'),
            **responses.response_template(404, example={"status": "Invalid key", "code": 1})
        }
        return response
    
    @staticmethod
    def MopSignal() -> responses_type:
        response: responses_type = {
            **responses.response_template(404, example={"Invalid Signal": {"status": "Invalid signal", "code": 1}, "Invalid Key": {"status": "Invalid key", "code": 1}}, multiple_examples=True),
            **responses.response_template(403, example={"status": "Cannot send any signal to public key", "code": 1}),
        }
        return response
    
    @staticmethod
    def MopEnd() -> responses_type:
        response: responses_type = {
            **responses.response_template(404, example={"status": "Invalid key", "code": 1}),
            **responses.response_template(500, example={"Invalid Client": {"status": "Client not found", "comment": "youre just as confused as i am. blame pylance","code": 1}, "Terminal Not Found": {"status": "Terminal not found", "code": 1}}),
            **responses.response_template(200, example={"Successful End": {"status": "Session ended", "code": 0}, "Successful End but ATTIC failure": {"status": "Session ended and failed to store to attic due to <error message>", "code": 0}})
        }
        return response
    
    @staticmethod
    def MopWrite() -> responses_type:
        response: responses_type = {
            **responses.response_template(200, example={"Successful Write": {"status": "Wrote data", "code": 0}, "Public Key Queue Write": {"status": "Put into queue", "position": 1, "code": 0}}, multiple_examples=True),
            **responses.response_template(404, example={"status": "Invalid key", "code": 1}),
            **responses.response_template(504, example={"status": "Write operation timed out", "code": 1}),
            **responses.response_template(428, example={"status": "MOP transaction not started", "code": 1}),
            **responses.response_template(410, example={"status": "Subprocess already terminated", "code": 1}),
            **responses.response_template(500, example={"Failure to write": {"status": "Failed to write to terminal: <Error Message>", "code": 1}, "Unexpected Error when writing": {"status": "Unexpected error: <Error Message>", "code": 1}}, multiple_examples=True),
            **responses.ratelimit("60 requests per minute")
        }
        return response
    
    @staticmethod
    def MopRead() -> responses_type:
        response: responses_type = {
            **responses.response_template(404, example={"status": "Invalid key", "code": 1}),
            **responses.response_template(500, example={"Invalid Client": {"status": "request.client is None", "comment": "Youre just as confused as i am. Blame Pylance", "code": 1}, "Reader EOF": {"status": "Task reached EOF", "code": 1}}, multiple_examples=True),
            **responses.response_template(200, example={"stdout": ["hello there.", "what is your name?"], "stderr": ["ooohh you got a error", "oh no"], "code": 0, "output_hash": "<md5 hash>"})
        }
        return response
    
    @staticmethod
    def MopWaiver() -> responses_type:
        response: responses_type = {
            **responses.response_template(403, example={"status": "Cannot set waiver for public key", "code": 1}),
            **responses.response_template(500, example={"status": "Unable to remove waiver"}),
            **responses.response_template(200, example={"Successful Waivers": {"status": "Waiver(s) set/removed", "code": 0}, "No Waivers Set": {"status": "No waivers set", "code": 0}}, multiple_examples=True),
            **responses.response_template(404, example={"Invalid Key": {"status": "Invalid key", "code": 1}, "Unknown Waiver": {"status": "Unknown waiver: waiver", "code": 1}}, multiple_examples=True)
        }
        return response
    
    @staticmethod
    def MopPing() -> responses_type:
        response: responses_type = {
            **responses.response_template(404, example={"status": "Session not found", "code": 1}),
            **responses.response_template(200, example={"status": "Process is alive", "code": 0}),
            **responses.response_template(410, example={"status": "Process is terminated", "code": 1})
        }
        return response
    
    @staticmethod
    def MopProcess() -> responses_type:
        response: responses_type = {
           **responses.response_template(428, example={"status": "No process is running.", "server_id": "894c0a23...", "command": "htop", "uptime": "6", "version": "1.1.1", "code": 0}),
           **responses.response_template(200, example={"server_id": "894c0a23...", "command": "htop", "uptime": "30", "sessions": 4, "pub_key": "445db74d...", "pending_writes": 2, "version": "1.0.0", "code": 0})
        }
        return response
    
    @staticmethod
    def Root() -> responses_type:
        response: responses_type = {
            **responses.response_template(400, example={"status": "use /mop/", "comment": "wrong url bud. its /mop","code": 0}),
            **responses.response_template(200, "text/plain", "I think you may have gotten the wrong url buddy.\nIf you are looking for MAT (webui) then change your port to 8080.\nIf you are looking for the api then its /mop")
        }
        return response
    
    
Plugin_Manifest: TypeAlias = dict[str, Plugin]

Session_storage: TypeAlias = dict[str, Union[PrivSession, PubSession]]