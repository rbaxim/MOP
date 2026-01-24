# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 rbaxim
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for details.
"""
Archived Terminal and Task Image Cache
"""
from fastapi import FastAPI, Request  # pyright: ignore[reportMissingImports]
from fastapi.responses import JSONResponse # pyright: ignore[reportMissingImports, reportMissingModuleSource]
from pathlib import Path 
import os
import aiofiles # pyright: ignore[reportMissingModuleSource]
import base64
from cryptography.fernet import Fernet, InvalidToken # pyright: ignore[reportMissingImports]
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # pyright: ignore[reportMissingImports]
from cryptography.hazmat.primitives import hashes # pyright: ignore[reportMissingImports]
import hashlib
import json
import logging
import psutil  # pyright: ignore[reportMissingModuleSource]
import aiohttp # pyright: ignore[reportMissingImports]
from colorama import Fore, Back, Style, init  # pyright: ignore[reportMissingModuleSource] # noqa: F401
import brotli_asgi # pyright: ignore[reportMissingImports]
import brotlicffi as brotli # pyright: ignore[reportMissingImports]
import zlib
import asyncio
import base91 # pyright: ignore[reportMissingImports]


init(autoreset=True)

app = FastAPI()

app.add_middleware(brotli_asgi.BrotliMiddleware, quality=6, gzip_fallback=True, minimum_size=256)

# CWD is mop
attic = Path(os.getcwd()) / Path("attic")

MAX_RAW_SIZE = 1_826_488_832 # GiB

async def folder_size_in_bytes(folder_path: str) -> int:
    folder = Path(folder_path)
    size = 0
    for f in folder.rglob('*'):
        if f.is_file():
            size += f.stat().st_size
            await asyncio.sleep(0)  # yield control
    return size


def compress_data(data: bytes) -> tuple[bytes, str]:
    # Try Brotli
    brotli_compressed = brotli.compress(data, quality=11)
    # Try zlib
    zlib_compressed = zlib.compress(data, level=9)

    if len(brotli_compressed) < len(zlib_compressed):
        return brotli_compressed, "brotli"
    else:
        return zlib_compressed, "zlib"

async def folder_size_in_gib(folder_path: str) -> float:
    """Return total folder size in GiB (binary)."""
    bytes_size = folder_size_in_bytes(folder_path)
    return await bytes_size / (1024**3)

if not attic.exists():
    logging.info("Creating attic directory")
    attic.mkdir()

if not (Path(os.getcwd()) / Path("logs")).exists():
    logging.info("Creating logs directory")
    (Path(os.getcwd()) / Path("logs")).mkdir()
    
current_attic = {}

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
    handlers=[
        logging.FileHandler("logs/attic.log"),
    ]
)

with open("pepper", "rb") as f:
    pepper: str = base91.decode(f.read().split("🌶️".encode("utf-8"))[0])
    
with open("auth/private_key.pem", "rb") as f:
    private_key = f.read().strip()
    
with open("auth/certificate.pem", "rb") as f:
    certificate = f.read().strip()
    
    
def big_hash(s) -> bytes:
    b = s if isinstance(s, bytes) else s.encode("utf-8")
    return hashlib.sha512(pepper.encode("utf-8") + b).digest()
    
static_secret = big_hash(private_key + certificate) # Type hints show string

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=pepper.encode("utf-8"),
    iterations=100_000,
)

fernet_key = base64.urlsafe_b64encode(kdf.derive(static_secret))
cipher_suite = Fernet(fernet_key)
            
async def read_file(path):
    async with aiofiles.open(path, mode='r') as f:
        contents = await f.read()
        return contents
    
async def read_bytes(path):
    async with aiofiles.open(path, mode='rb') as f:
        contents = await f.read()
        return contents
    
async def write_file(path, text):
    async with aiofiles.open(path, mode='w') as f:
        await f.write(text)
        
async def write_bytes(path, text):
    safe_path = Path(path).name 
    final_path = attic / safe_path

    async with aiofiles.open(final_path, mode='wb') as f:
        await f.write(text)
        
        
for path in attic.iterdir():
    if path.is_file() and path.suffix == ".attic":
        logging.info(f"Loading {path.name}")
        current_attic[path.stem] = path.read_bytes()
        
def get_tcp_listening_ports(pid):
    """
    Retrieves all TCP listening ports for a given process ID (PID).
    """
    try:
        p = psutil.Process(int(pid))
        # Get all connections for the process, filtered by TCP
        connections = p.net_connections(kind='tcp')
        listening_ports = []
        for conn in connections:
            # Check if the connection status is LISTEN
            if conn.status == psutil.CONN_LISTEN:
                # laddr is a named tuple (ip, port)
                listening_ports.append(conn.laddr.port)
                logging.info(f"Found listening TCP port: {conn.laddr.port}")
                print(f"{Fore.GREEN}INFO{Fore.RESET}:     Found listening TCP port: {conn.laddr.port}.")
                print()
        return listening_ports
    except psutil.NoSuchProcess:
        print(f"Error: No process found with PID {pid}")
        return []
    except psutil.AccessDenied:
        print(f"Error: Access denied for PID {pid}. Try running as root/administrator.")
        return []

async def get_mop_port(pid):
    listening_ports = get_tcp_listening_ports(pid)
    async with aiohttp.ClientSession() as session:
        for port in listening_ports:
            try:
                async with session.head(f"http://localhost:{port}/") as response:
                    if ("X-MOP") in response.headers:
                        logging.info(f"Found MOP Port: {port}")
                        print(f"{Fore.GREEN}INFO{Fore.RESET}:     Found MOP Port: {port}.")
                        return port 
                    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Port {port} is not MOP.")
                    logging.info(f"Port {port} is not MOP")
            except Exception:
                pass
    return None    
    
async def reload_attic():
    global current_attic
    current_attic = {}
    logging.info("Reloading attic")
    for f in attic.iterdir():
        if f.is_file() and f.suffix == ".attic":
            logging.info(f"Loading {f}")
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Loading {f}.")
            current_attic[f.stem] = await read_bytes(str(f))    

@app.get("/")
async def root():
    return JSONResponse({"route": "attic"}, status_code=200)

@app.post("/attic/store")
async def store(request: Request):
    data = await request.json()
    key = data.get("key") # Trusts that the key is hashed already
    pid = data.get("pid")
    
    port = await get_mop_port(pid)
    
    store_data = {
        "program": data.get("program"),
        "pickle": data.get("pickle", {}),
        "port": port if port is not None else "Not Found"
    }
    
    compressed_data = compress_data(json.dumps(store_data).encode("utf-8"))
    
    payload = {
        "method": compressed_data[1],
        "data": base64.b85encode(compressed_data[0]).decode("utf-8")
    }

    encrypted_data = cipher_suite.encrypt(json.dumps(payload).encode("utf-8"))
    
    folder_size = await folder_size_in_gib(str(attic))
    
    data_size = len(encrypted_data) / (1024**3)
    
    if folder_size + data_size > MAX_RAW_SIZE / (1024**3):
        logging.info(f"{Fore.GREEN}WARNING{Fore.RESET}:     Attic is full. Denying new data.")
        logging.info(f"{Fore.GREEN}WARNING{Fore.RESET}:     Current folder size: {folder_size} GiB, {key[:6]} data size: {data_size} GiB")
        return JSONResponse({"status": "Attic is full"}, status_code=400)
    
    logging.info(f"Storing {key[:6]} in attic")
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Storing {key[:6]} in attic.")
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Folder size: {folder_size} GiB")
    if port is not None:
        logging.info(f"Unable to find MOP port for {key[:6]}")
        print(f"{Fore.GREEN}WARNING{Fore.RESET}:     Unable to find MOP port for {key[:6]}.")
    await write_bytes(str(attic / f"{key}.attic"), encrypted_data)
    current_attic[key] = encrypted_data
    return JSONResponse({"status": f"Stored{' but no MOP port was found' if port is None else ''}"}, status_code=200)
    
@app.post("/attic/retrieve")
async def retrieve(request: Request):
    data = await request.json()
    key = data.get("key") # Trusts that the key is hashed already
    if key not in current_attic.keys():
        return JSONResponse({"status": "Not found"}, status_code=404)
    try:
        decrypted_data = json.loads(cipher_suite.decrypt(current_attic[key]).decode("utf-8"))
        method = decrypted_data.get("method")
        compressed_bytes = base64.b85decode(decrypted_data.get("data").encode("utf-8"))
        try:
            if method == "brotli":
                new_data = json.loads(brotli.decompress(compressed_bytes))
            elif method == "zlib":
                new_data = json.loads(zlib.decompress(compressed_bytes))
            else:
                logging.info(f"Corrupted data for {key[:6]} in attic")
                print(f"{Fore.GREEN}ERROR{Fore.RESET}:     Corrupted data for {key[:6]} in attic.")
                return JSONResponse({"status": "Corrupted data"}, status_code=500)
        except Exception:
            logging.info(f"Corrupted data for {key[:6]} in attic")
            print(f"{Fore.GREEN}ERROR{Fore.RESET}:     Corrupted data for {key[:6]} in attic.")
            return JSONResponse({"status": "Corrupted data"}, status_code=500)
    except InvalidToken:
        logging.info(f"Corrupted data for {key[:6]} in attic")
        print(f"{Fore.GREEN}ERROR{Fore.RESET}:     Corrupted data for {key[:6]} in attic.")
        return JSONResponse({"status": "Corrupted data"}, status_code=500)
    except json.JSONDecodeError:
        print(f"{Fore.GREEN}ERROR{Fore.RESET}:     Corrupted data for {key[:6]} in attic.")
        logging.info(f"Corrupted data for {key[:6]} in attic")
        return JSONResponse({"status": "Corrupted data"}, status_code=500)
    
    get_data = {
        "program": new_data.get("program"),
        "pickle": new_data.get("pickle"),
        "port": new_data.get("port", "Not Found")
    }
    logging.info(f"Retrieved {key[:6]} from attic")
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Retrieved {key[:6]} from attic.")
    return JSONResponse(get_data, status_code=200)

@app.post("/attic/delete")
async def delete(request: Request):
    data = await request.json()
    key = data.get("key") # Trusts that the key is hashed already
    if key not in current_attic:
        return JSONResponse({"status": "Not found"}, status_code=404)
    safe_name = Path(f"{key}.attic").name
    target_path = attic / safe_name
    if target_path.exists():
        target_path.unlink()
    del current_attic[key]
    logging.info(f"Deleted {key[:6]} from attic")
    print(f"{Fore.GREEN}INFO{Fore.RESET}:     Deleted {key[:6]} from attic.")
    return JSONResponse({"status": "Deleted"}, status_code=200)

@app.post("/attic/proc/tell")
async def tell(request: Request):
    data = await request.json()
    key = data.get("key") # Trusts that the key is hashed already
    info = data.get("info")
    if key not in current_attic:
        logging.info(f"Unable to find {key[:6]} in attic")
        print(f"{Fore.GREEN}ERROR{Fore.RESET}:     Unable to find {key[:6]} in attic.")
        return JSONResponse({"status": "Not found"}, status_code=404)
    if not info:
        logging.info(f"Missing info from request with {key[:6]}")
        print(f"{Fore.GREEN}WARNING{Fore.RESET}:     Missing info from request with {key[:6]}")
        return JSONResponse({"status": "Missing info"}, status_code=400)
    
    decrypted = json.loads(cipher_suite.decrypt(current_attic[key]).decode("utf-8"))
    port = decrypted.get("port", "Not Found")
    
    if port == "Not Found":
        logging.info(f"Unable to find MOP port for {key[:6]}")
        print(f"{Fore.GREEN}WARNING{Fore.RESET}:     Unable to find MOP port for {key[:6]}")
        return JSONResponse({"status": "Unable to get port"}, status_code=500)
    
    async with aiohttp.ClientSession() as session:
        async with session.post(f"http://localhost:{port}/mop/session", json={"data": info}) as response:
            logging.info(f"Telling {key[:6]} some data")
            print(f"{Fore.GREEN}INFO{Fore.RESET}:     Telling {key[:6]} some data.")
            return JSONResponse(await response.json(), status_code=response.status)