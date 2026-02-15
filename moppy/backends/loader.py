"""
i love legos :3
"""
import moppy.utils as utils
from dataclasses import dataclass
import importlib
import logging
import json
from typing import TypedDict, Union, Literal, Optional, Callable

root = utils.moppy_dir("").parent

logging.basicConfig(
    format="%(message)s",
    level=logging.DEBUG,
    handlers=[
        logging.FileHandler(root / "mop.log"),
    ],
)

class terminal_metadata(TypedDict):
    id: str
    version: str
    os_supported: list[Union[Literal["unix"], Literal["win32"]]]
    method_supported: list[Union[Literal["pipe"], Literal["pty"]]]
    terminal_reference: Optional[str]
    spawn_tty_reference: Optional[str]
    spawn_pipe_reference: Optional[str]
    
class datastore_metadata(TypedDict):
    id: str
    version: str
    datastore_reference: Optional[str]

@dataclass
class Terminal_Module:
    Terminal: type
    spawn_tty: Optional[Callable]
    spawn_pipe: Optional[Callable]
    metadata: terminal_metadata
    
@dataclass
class Datastore_Module:
    Datastore: type
    metadata: datastore_metadata
    
def spawn_tty(*args, **kwargs):
    raise NotImplementedError("Terminal Backend does not support spawn_tty()")

def spawn_pipe(*args, **kwargs):
    raise NotImplementedError("Terminal Backend does not support spawn_pipe()")

def load_terminal(name: str) -> Terminal_Module:
    try:
        module = importlib.import_module(f"moppy.backends.Terminal.{name}")
    except ImportError as e:
        logging.error("[ERROR] Terminal not found!")
        raise ImportError(f"Terminal {name} not found!") from e
    
    step = "Reading metadata"
    
    spawn_tty_reference = "Not Implemented"
    
    spawn_pipe_reference = "Not Implemented"
    
    metadata: terminal_metadata = {} # type: ignore
    
    if hasattr(module, "metadata"):
        try:
            logging.info(f"[INFO] Loading metadata for {name}")
            step = f"{name}.metadata.id"
            logging.info(f"[INFO] ID: {module.metadata.id}")
            metadata["id"] = module.metadata.id
            step = f"{name}.metadata.version"
            logging.info(f"[INFO] Version: {module.metadata.version}")
            metadata["version"] = module.metadata.version
            step = f"{name}.metadata.os_supported"
            logging.info(f"[INFO] OS Supported: {module.metadata.os_supported}")
            metadata["os_supported"] = module.metadata.os_supported
            step = f"{name}.metadata.method_supported"
            logging.info(f"[INFO] Method Supported: {module.metadata.method_supported}")
            metadata["method_supported"] = module.metadata.method_supported
            step = f"{name}.metadata.terminal_reference"
            try: # Account for custom terminal in metadata
                terminal_reference = module.metadata.terminal_reference
            except AttributeError: # No reference, OK we just default to Terminal
                terminal_reference = "Terminal"
            
            
            if "pty" in metadata["method_supported"]:
                step = f"{name}.metadata.tty_reference"
                try: # Account for custom tty name in metadata
                    spawn_tty_reference = module.metadata.spawn_tty_reference
                except AttributeError: # No reference, OK we just default to spawn_tty
                    spawn_tty_reference = "spawn_tty"
            
            if "pipe" in metadata["method_supported"]:
                step = f"{name}.metadata.pipe_reference"
                try: # Account for custom pipe name in metadata
                    spawn_pipe_reference = module.metadata.spawn_pipe_reference
                except AttributeError: # No reference, OK we just default to spawn_tty
                    spawn_pipe_reference = "spawn_pipe" 
            
            step = "Complete!"
        except AttributeError as e:
            logging.error(f"[ERROR] Failed to load terminal metadata! Module has no metadata! Failure at step: {step}")
            raise ValueError(f"Failed to load terminal metadata! Failure at step: {step}") from e
    else:
        logging.error("[ERROR] Failed to load terminal metadata! Module has no metadata!")
        raise ValueError("Failed to load terminal metadata! Module has no metadata!")
    
    logging.info(f"[INFO] Loading Terminal for {name}")
    if hasattr(module, terminal_reference):
        spawn_tty_code = getattr(module, spawn_tty_reference) if "pty" in metadata["method_supported"] else spawn_tty
        spawn_pipe_code = getattr(module, spawn_pipe_reference) if "pipe" in metadata["method_supported"] else spawn_pipe
        return Terminal_Module(getattr(module, terminal_reference), spawn_tty_code, spawn_pipe_code, metadata)
    else:
        logging.error("[ERROR] Failed to load terminal! Module has no terminal class! Either set metadata.terminal_reference or add a Terminal class to the module!")
        raise ValueError("Failed to load terminal! Module has no terminal class! Either set metadata.terminal_reference or add a Terminal class to the module!")
    
def load_datastore(name: str) -> Datastore_Module:
    try:
        module = importlib.import_module(f"moppy.backends.Datastore.{name}")
    except ImportError as e:
        logging.error("[ERROR] Datastore not found!")
        raise ImportError(f"Datastore {name} not found!") from e
    
    metadata: datastore_metadata = {} # type: ignore

    step = "Reading metadata"
    if hasattr(module, "metadata"):
        try:
            logging.info(f"[INFO] Loading metadata for {name}")
            step = f"{name}.metadata.id"
            logging.info(f"[INFO] ID: {module.metadata.id}")
            metadata["id"] = module.metadata.id
            step = f"{name}.metadata.version"
            logging.info(f"[INFO] Version: {module.metadata.version}")
            metadata["version"] = module.metadata.version
            step = f"{name}.metadata.datastore_reference"
            try: # Account for custom datastore in metadata
                datastore_reference = module.metadata.datastore_reference
            except AttributeError: # No reference, OK we just default to Datastore
                datastore_reference = "Datastore"
        except AttributeError as e:
            logging.error(f"[ERROR] Failed to load datastore metadata! Module has no metadata! Failure at step: {step}")
            raise ValueError(f"Failed to load datastore metadata! Module has no metadata! Failure at step: {step}") from e
    else:
        logging.error("[ERROR] Failed to load datastore metadata! Module has no metadata!")
        raise ValueError("Failed to load datastore metadata! Module has no metadata!")
    
    logging.info(f"[INFO] Loading Datastore for {name}")
    if hasattr(module, datastore_reference):
        return Datastore_Module(getattr(module, datastore_reference), metadata)
    else:
        logging.error("[ERROR] Failed to load datastore! Module has no datastore class! Either set metadata.datastore_reference or add a Datastore class to the module!")
        raise ValueError("Failed to load datastore! Module has no datastore class! Either set metadata.datastore_reference or add a Datastore class to the module!")
    
def read_config() -> dict:
    with open(utils.moppy_dir("config.json"), "r") as f:
        return json.loads(f.read())