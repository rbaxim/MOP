"""
offbrand redis
"""
from multiprocessing.managers import BaseManager
from multiprocessing import Queue, Lock
from multiprocessing.synchronize import Lock as LockType
from dataclasses import dataclass
from moppy.utils import steal_port
import os
from queue import Empty
import time
from typing import TypedDict, Any, cast

@dataclass
class metadata:
    id: str = "default"
    version: str = "1.0.0"

class Manager(BaseManager): 
    pass

class TerminalEntry(TypedDict):
    keys: list[str]
    queue: Queue
    responses: list[dict]
    responses_lock: LockType
    
class ManagerTypes:
    def terminal_list(self) -> dict[int, TerminalEntry]: ... # type: ignore
    def server_data(self) -> dict[str, Any]: ... # type: ignore
    def Queue(self) -> Queue: ... # type: ignore
    def list(self) -> list: ... # type: ignore 
    def lock(self) -> LockType: ... # type: ignore
    def connect(self): ... # type: ignore
    

class Datastore:
    @staticmethod
    def create_manager(port=50000, authkey=b""):
        steal_port(port, True)
        shared_terminal_list: dict[int, TerminalEntry] = {}
        shared_server_data: dict[str, Any] = {}
        Manager.register("lock", Lock, exposed=["acquire", "release", "__enter__", "__exit__"])
        Manager.register("terminal_list", callable=lambda: shared_terminal_list)
        Manager.register("server_data", callable=lambda: shared_server_data, exposed=["__getitem__", "__setitem__", "__delitem__", "get", "items", "keys", "values"])
        Manager.register("Queue", Queue)
        Manager.register("list", list, exposed=["__iter__", "__len__", "__getitem__", "append", "remove", "__contains__", "pop"])
        manager = Manager(address=("127.0.0.1", port))
        manager.start()
        return manager

    def __init__(self, port=50000, authkey=b""):
        Manager.register("terminal_list")
        Manager.register("server_data")
        Manager.register("Queue")
        Manager.register("list")
        Manager.register("lock")
        self.manager = cast(ManagerTypes, Manager(address=("127.0.0.1", port))) # I know this looks cursed but its required
        self.manager.connect()
        try:
            self.datastore: dict = self.manager.terminal_list() # type: ignore
        except AttributeError as e:
            raise NameError("Manager was not initalized.") from e
        self.server_data: dict = self.manager.server_data() # pyright: ignore[reportAttributeAccessIssue]
        
        self.datastore.update({os.getpid(): {"keys": self.manager.list(), "queue": self.manager.Queue(), "responses": self.manager.list(), "responses_lock": self.manager.lock()}}) # pyright: ignore[reportAttributeAccessIssue]
    def register(self, key):
        proc_datastore = self.datastore.setdefault(os.getpid(), {
            "keys": self.manager.list(), # pyright: ignore[reportAttributeAccessIssue]
            "queue": self.manager.Queue(), # pyright: ignore[reportAttributeAccessIssue]
            "responses": self.manager.list(), # pyright: ignore[reportAttributeAccessIssue]
            "responses_lock": self.manager.lock() # pyright: ignore[reportAttributeAccessIssue]
        })

        proc_datastore["keys"].append(key)
    
    def unregister(self, key):
        proc_datastore = self.datastore.get(os.getpid())
        if proc_datastore is None:
            return  # nothing to remove
        keys = proc_datastore.get("keys")
        if keys is not None and key in keys:
            keys.remove(key)
        
    def _get_terminal(self, key):
        for pid, entry in self.datastore.items():
            keys = entry.get("keys")
            if keys is not None and key in keys:
                return pid, entry
        return None, None
    
    def request(self, key, payload, id):
        pid, content = self._get_terminal(key)
        if pid is None or content is None:
            return False
        # Use the queue proxy's put method (thread-safe)
        content["queue"].put({"from": os.getpid(), "payload": payload, "id": id, "timestamp": time.monotonic()})
        return True

    def check_requests(self):
        proc_datastore = self.datastore.get(os.getpid())
        if proc_datastore is None:
            return None
        queue = proc_datastore.get("queue")
        if queue is None:
            return None
        try:
            request = queue.get_nowait()
            # Allow enough time for cross-process scheduling jitter.
            if time.monotonic() - request.get("timestamp", 0) > 5.0:
                return None
            return request
        except (Empty, EOFError, BrokenPipeError):
            return None
           
    def response(self, source, key, payload, id):
        # Route responses to the requesting process so it can consume locally.
        proc_datastore = self.datastore.get(source)
        if proc_datastore is None:
            return
        lock = proc_datastore.get("responses_lock")
        responses = proc_datastore.get("responses")
        if responses is not None and lock is not None:
            with lock:
                responses.append({"to": source, "key": key, "payload": payload, "id": id})
        
    def check_response(self, key, id):
        proc_datastore = self.datastore.get(os.getpid())
        if proc_datastore is None:
            return None
        lock = proc_datastore.get("responses_lock")
        responses = proc_datastore.get("responses")
        if responses is None or lock is None:
            return None

        with lock:
            for i, mail in enumerate(responses):
                if mail["id"] == id and mail["key"] == key:
                    response = responses.pop(i)
                    return response.get("payload")
        return None
    
    def cleanup(self):
        if os.getpid() in self.datastore:
            del self.datastore[os.getpid()]
        worker_key = f"worker:{os.getpid()}"
        if worker_key in self.server_data:
            del self.server_data[worker_key]
    
    def create_queue(self):
        return self.manager.Queue() # pyright: ignore[reportAttributeAccessIssue]

    def set_server_value(self, key, value):
        self.server_data[key] = value

    def get_server_value(self, key, default=None):
        return self.server_data.get(key, default)

    def get_server_data(self):
        return dict(self.server_data)
