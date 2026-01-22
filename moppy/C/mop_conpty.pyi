from typing import Awaitable

class ConPTY:
    """
    High-performance Windows ConPTY interface providing direct access to the Windows
    Pseudoconsole (ConPTY) API with asynchronous I/O support.
    
    This class provides a native interface to Windows ConPTY with minimal overhead,
    supporting full terminal fidelity, signal propagation, and asynchronous operations.
    """
    
    def __init__(self, command: str, cols: int = 80, rows: int = 24, cwd: str = ".", env: dict[str, str] = {}) -> None:
        """
        Create a new ConPTY instance and spawn a subprocess.
        
        Args:
            command: The command to execute (e.g., "powershell.exe", "cmd.exe")
            cols: Terminal width in columns (default: 80)
            rows: Terminal height in rows (default: 24)
            cwd: Working directory for the subprocess
            env: Environment variables for the subprocess
        
        Raises:
            RuntimeError: If ConPTY API is not available (Windows < 10 1809)
            OSError: If process creation fails
        """
        ...
    
    @property
    def pid(self) -> int:
        """
        Get the process ID of the child process.
        
        This PID can be used with psutil or other process monitoring tools.
        
        Returns:
            The child process ID
        """
        ...
    
    def set_echo(self, enable: bool) -> None:
        """
        Enable or disable echo input mode.
        
        When disabled, typed characters are not echoed back to the terminal,
        preventing double-typing issues in interactive applications.
        
        Args:
            enable: True to enable echo, False to disable it
        """
        ...
    
    def send_signal(self, sig_type: int) -> None:
        """
        Send a control signal to the child process.
        
        Supported signal types:
        - 0: CTRL_C_EVENT (Ctrl+C)
        - 1: CTRL_BREAK_EVENT (Ctrl+Break)
        
        Args:
            sig_type: The signal type to send (0 or 1)
        
        Raises:
            ValueError: If an unsupported signal type is provided
            OSError: If signal delivery fails
        """
        ...
    
    def read_async(self) -> Awaitable[bytes]:
        """
        Asynchronously read data from the terminal output.
        
        This method reads raw bytes from the terminal without blocking the event loop.
        The returned awaitable will resolve with the read data when available.
        
        Returns:
            An awaitable that resolves to bytes containing terminal output
        
        Note:
            Returns empty bytes when the terminal is closed or EOF is reached.
        """
        ...
    
    def write_async(self, data: bytes) -> Awaitable[int]:
        """
        Asynchronously write data to the terminal input.
        
        This method writes raw bytes to the terminal input stream without blocking
        the event loop. The returned awaitable will resolve with the number of bytes
        actually written.
        
        Args:
            data: Bytes to write to the terminal input
        
        Returns:
            An awaitable that resolves to the number of bytes written
        """
        ...
    
    def close(self) -> None:
        """
        Close the pseudoconsole and terminate the child process.
        
        This method cleans up all resources associated with the ConPTY instance
        and terminates the child process if it's still running.
        
        Note:
            This method is idempotent and can be called multiple times safely.
        """
        ...

__version__: str
"""
The version of the mop_conpty extension module.
"""

def spawn(command: str, cols: int = 80, rows: int = 24) -> ConPTY:
    """
    Convenience function to create a ConPTY instance.
    
    This is equivalent to ConPTY(command, cols, rows).
    
    Args:
        command: The command to execute
        cols: Terminal width in columns
        rows: Terminal height in rows
    
    Returns:
        A new ConPTY instance
    """
    ...

# Type aliases for common patterns
StreamData = bytes
SignalType = int

# Constants for signal types
CTRL_C_EVENT: int = 0
CTRL_BREAK_EVENT: int = 1

# Exception types that may be raised
class ReadError(Exception):
    """Raised when a read operation fails."""
    ...

class WriteError(Exception):
    """Raised when a write operation fails."""
    ...

class ConPTYError(Exception):
    """Base exception for all ConPTY-related errors."""
    ...