"""
hahahaha i am good at my job.
"""
import sys
from typing import Optional, cast, Any, Union
import asyncio
import moppy.utils as utils
import os
import base64
import signal
import logging
from pathlib import Path
import subprocess
import shutil

moppy_dir = utils.moppy_dir # copy paste good

def is_pypy():
    return '__pypy__' in sys.builtin_module_names

root = moppy_dir("").parent

logging.basicConfig(
    format="%(message)s",
    level=logging.DEBUG,
    handlers=[
        logging.FileHandler(root / "mop.log"),
    ],
)

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

IS_CONPTY_AVAILABLE = False
if sys.platform == "win32":
    try:
        if not is_pypy():
            import ConPTYBridge.conpty as conpty
            IS_CONPTY_AVAILABLE = True
            conpty_dll_path = root / "ConPTYBridge/bin/Release/net8.0/ConPTYBridge.dll"
    except ImportError:
        logging.warning("[WARNING]  You are not using the C# ConPTY wrapper for python. It is heavily recommended you install/build it for extra features")
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

class metadata:
    id: str = "default"
    version: str = "1.0.0"
    os_supported: list[str] = ["unix", "win32"]
    method_supported: list[str] = ["pipe", "pty"]

class Terminal:
    def __init__(self, proc: Optional[asyncio.subprocess.Process] = None, master_fd: Optional[int]=None, pty_obj: Optional[Union['winpty.PTY', "conpty.ConPTYInstance"]]=None, use_pipes: bool = False): # type: ignore[name-defined, valid-type]
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
                logging.info("[INFO] Terminal closed due to EOF")
                self.close()
                return
            self._read_buffer.extend(data)
        except BlockingIOError:
            return
        except OSError as e:
            logging.error(f"[ERROR] Failed to read from terminal due to {str(e)}")
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
                logging.error(f"[ERROR] Failed to read from terminal during prime: {e}")
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
                logging.error(f"[ERROR] Failed to send signal to {self.proc.pid}. Process unexepectedly died?")
                pass
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
                        logging.debug("BlockingIOError catched. Retrying write...")
                    except (asyncio.TimeoutError, asyncio.CancelledError):
                        logging.debug("Write Timeout exceeded")
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
        
    @property
    def is_alive(self) -> bool:
        if sys.platform == "win32":
            pty = cast(Union["conpty.ConPTYClient","winpty.pty"], self.pty)
            if IS_CONPTY_AVAILABLE:
                pty = cast(conpty.ConPTYClient, self.pty)
                is_alive = pty.is_alive()
            else:
                pty = cast(winpty.PTY, self.pty)
                is_alive = pty.is_alive()
        else:
            is_alive = cast(asyncio.subprocess.Process, self.proc).returncode is None
        
        return is_alive
    

async def spawn_tty(command: list[str], disable_echo=True, cwd: str = os.getcwd()) -> Terminal:
    new_cwd = Path(cwd).expanduser().resolve().absolute()
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
    
async def spawn_pipe(command: list[str], cwd: str = os.getcwd()):
    new_cwd = Path(cwd).resolve()
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