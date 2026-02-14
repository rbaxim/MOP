# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 rbaxim
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for details
"""
C# != Python? ehh i see no difference
"""
from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING, Any, Optional, Tuple
import sys

if sys.platform != "win32":
    raise RuntimeError("ConPTYBridge is only supported on Windows")

from pythonnet import load  # pyright: ignore[reportMissingImports]

# ============================================================
# 1. Init .NET runtime FIRST
# ============================================================

load("coreclr")
import clr  # type: ignore  # noqa: E402

from ctypes import wintypes  # noqa: E402
from Microsoft.Win32.SafeHandles import SafeFileHandle  # type: ignore  # noqa: E402
from System import IntPtr, UInt32  # type: ignore  # noqa: E402
from System.Collections.Generic import Dictionary  # type: ignore  # noqa: E402


# ============================================================
# 2. Static typing shim for pythonnet dynamic types
# ============================================================

if TYPE_CHECKING:
    class ConPTYInstance:  # type: ignore[no-redef]
        Pid: int
        Cwd: str
        EnvVars: dict[str, str]

        def __init__(self, writeEnd: SafeFileHandle, readEnd: SafeFileHandle) -> None: ...
        def Create(
            self,
            width: int,
            height: int,
            ptyInputRead: SafeFileHandle,
            ptyOutputWrite: SafeFileHandle,
            flags: int = 0,
        ) -> None: ...

        def Start(self, commandLine: str, cwd: str, envVars: Optional[Dictionary[str, str]]) -> None: ...
        def Write(self, data: bytes) -> None: ...
        def Read(self, bufferSize: int = 4096) -> bytes: ...
        def Dispose(self) -> None: ...
        def ExitCode(self) -> int: ...
        def IsAlive(self) -> bool: ...

else:
    ConPTYInstance = Any  # runtime placeholder


# ============================================================
# 3. Win32 pipe helpers
# ============================================================

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


def _create_pipe() -> Tuple[int, int]:
    h_read = wintypes.HANDLE()
    h_write = wintypes.HANDLE()

    ok = _kernel32.CreatePipe(
        ctypes.byref(h_read),
        ctypes.byref(h_write),
        None,
        0,
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    return int(h_read.value), int(h_write.value) # pyright: ignore[reportArgumentType]


# ============================================================
# 4. Main Client (RAW I/O)
# ============================================================

class ConPTYClient:
    """
    Raw, pull-based PTY client.

    No background threads.
    No printing.
    Caller controls read/write and event loop.
    """

    def __init__(self, dll_path: str) -> None:
        self._dll_path: str = dll_path

        # Load CLR assembly
        clr.AddReference(dll_path)  # pyright: ignore[reportAttributeAccessIssue]

        # Import real CLR type after AddReference
        global ConPTYInstance
        from Moppy.ConPTY import ConPTYInstance as _ConPTYInstance  # type: ignore

        ConPTYInstance = _ConPTYInstance  # type: ignore[assignment, misc]

        self._pty: Optional[ConPTYInstance] = None

        self._pty_in_r: Optional[int] = None
        self._py_in_w: Optional[int] = None
        self._py_out_r: Optional[int] = None
        self._pty_out_w: Optional[int] = None

    # --------------------------------------------------------
    # Lifecycle
    # --------------------------------------------------------

    def start(self, command: str, cols: int = 80, rows: int = 24, flags: int = 0, cwd: str="", env: dict[str, str] | None = None) -> None:
        # Create pipes
        self._pty_in_r, self._py_in_w = _create_pipe()
        self._py_out_r, self._pty_out_w = _create_pipe()

        # Create PTY instance
        self._pty = ConPTYInstance(
            SafeFileHandle(IntPtr(self._py_in_w), True),
            SafeFileHandle(IntPtr(self._py_out_r), True),
        )

        # Create pseudoconsole
        self._pty.Create(
            cols,
            rows,
            SafeFileHandle(IntPtr(self._pty_in_r), True),
            SafeFileHandle(IntPtr(self._pty_out_w), True),
            UInt32(flags),
        )

        # Build CLR Dictionary if env is provided
        clr_env = None
        if env is not None:
            clr_env = Dictionary[str, str]()
            for k, v in env.items():
                clr_env[k] = v

        # Start process with optional environment block
        self._pty.Start(command, cwd, clr_env)

    # --------------------------------------------------------
    # Properties
    # --------------------------------------------------------

    @property
    def pid(self) -> int:
        if not self._pty:
            raise RuntimeError("PTY not started")
        return int(self._pty.Pid)

    # --------------------------------------------------------
    # Raw I/O
    # --------------------------------------------------------

    def write(self, data: bytes) -> None:
        """
        Write raw bytes to PTY exactly as provided.
        """
        if not self._pty:
            raise RuntimeError("PTY not started")

        self._pty.Write(data)

    def read(self, max_bytes: int = 4096) -> bytes:
        """
        Read raw bytes from PTY (non-blocking).

        Returns b"" if no data is available.
        """
        if not self._pty:
            raise RuntimeError("PTY not started")

        return bytes(self._pty.Read(max_bytes))

    # --------------------------------------------------------
    # Process state
    # --------------------------------------------------------

    def is_alive(self) -> bool:
        if not self._pty:
            return False
        return bool(self._pty.IsAlive())

    def exit_code(self) -> Optional[int]:
        if not self._pty:
            return None
        return int(self._pty.ExitCode())

    # --------------------------------------------------------
    # Shutdown
    # --------------------------------------------------------

    def close(self) -> None:
        if self._pty:
            try:
                self._pty.Dispose()
            except Exception:
                pass

        self._pty = None