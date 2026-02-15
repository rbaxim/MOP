from multiprocessing.managers import BaseManager
from multiprocessing import Queue
from dataclasses import dataclass
from moppy.utils import steal_port, moppy_dir
from typing import BinaryIO, cast
import base91 # pyright: ignore[reportMissingImports]
import sys
import os
from queue import Empty

try:
    f_pepper: BinaryIO 
    with open(moppy_dir("pepper"), "rb") as f_pepper:
        f_pepper = cast(BinaryIO, f_pepper)
        pepper = bytes(base91.decode(f_pepper.read().split("🌶️".encode("utf-8"))[0]))
    
    if sys.platform != "win32":
        os.chmod(moppy_dir("pepper"), 0o600)
except FileNotFoundError:
    # Server should have generated it already
    sys.exit(1)

@dataclass
class metadata:
    id: str = "default"
    version: str = "1.0.0"

class Manager(BaseManager): 
    pass

class Datastore:
    @staticmethod
    def create_manager(port=50000):
        steal_port(port, True)
        Manager.register("terminal_list", dict)
        Manager.register("Queue", Queue)
        manager = Manager(address=("127.0.0.1", port), authkey=pepper)
        manager.start()
        return manager

    def __init__(self, port):
        Manager.register("terminal_list")
        self.manager = Manager(address=("127.0.0.1", port), authkey=pepper)
        self.manager.connect()
        try:
            self.datastore: dict = self.manager.terminal_list() # pyright: ignore[reportAttributeAccessIssue]
        except AttributeError as e:
            raise NameError("Manager was not initalized.") from e
        
        self.datastore[os.getpid()] = {"keys": self.manager.list(), "queue": self.manager.Queue(), "responses": self.manager.list()} # pyright: ignore[reportAttributeAccessIssue]
    
    def register(self, key):
        self.datastore[os.getpid()]["keys"].append(key)
    
    def unregister(self, key):
        self.datastore[os.getpid()]["keys"].remove(key)
        
    def _get_terminal(self, key):
        for name, value in self.datastore.items():
            if key in value["keys"]:
                return name, value
        
        return None, None
    
    def request(self, key, payload, id):
        pid, content = self._get_terminal(key)
        if pid is None or content is None:
            raise ValueError("Invalid Key")
        
        content["queue"].put({"from": os.getpid(), "payload": payload, "id": id})
        return True
    
    def check_requests(self):
        try:
            return self.datastore[os.getpid()]["queue"].get_nowait()
        except (Empty, EOFError, BrokenPipeError):
            return None
        
    def response(self, source, key, payload, id):
        self.datastore[os.getpid()]["responses"].append({"to": source, "key": key, "payload": payload, "id": id})
        
    def check_response(self, key, id):
        pid, content = self._get_terminal(key)
        if pid is None or content is None:
            raise ValueError("Invalid Key")

        responses = list(self.datastore[pid]["responses"])
        for mail in responses:
            if mail["id"] == id and mail["key"] == key and mail["to"] == os.getpid(): # Success. this is our mail
                self.datastore[pid]["responses"].remove(mail)
                return mail["payload"]
        
        return None
    
    def cleanup(self):
        if os.getpid() in self.datastore:
            del self.datastore[os.getpid()]