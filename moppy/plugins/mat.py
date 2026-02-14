# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 rbaxim
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for details.
"""
Modular Application Terminal
"""
from fastapi import FastAPI, Request # pyright: ignore[reportMissingImports]
from fastapi.responses import HTMLResponse, FileResponse, PlainTextResponse, JSONResponse, RedirectResponse, Response # pyright: ignore[reportMissingImports]
import hashlib
import aiohttp # pyright: ignore[reportMissingImports]
import ssl
import logging
import brotlicffi as brotli # pyright: ignore[reportMissingImports]
import gzip # pyright: ignore[reportMissingImports]
from contextlib import asynccontextmanager # pyright: ignore[reportMissingImports]
import asyncio

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.timeout = aiohttp.ClientTimeout(total=10, connect=5, sock_connect=5, sock_read=5)
    app.state.session = aiohttp.ClientSession(timeout=app.state.timeout)
    app.state.ssl_context = make_ssl_context()
    yield
    await app.state.session.close()

app = FastAPI(lifespan=lifespan)

def make_ssl_context():
    try:
        # Sadly, for some reason this stopped working
        ctx = ssl.create_default_context(cafile="./certs/cert.pem")
        
        # time to disable verification :(
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    except Exception:
        # http, main server warns about this. so its usually safe in this case
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    return ctx

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
    handlers=[
        logging.FileHandler("logs/mat.log"),
    ]
)

app.state.mop_scheme = None 


async def fetch_backend(path: str, method="GET", body=None, headers=None):
    ssl_context = app.state.ssl_context
    urls = [
        ("https", f"https://localhost:8000/{path}"),
        ("https", f"https://127.0.0.1:8000/{path}"),
        ("http",  f"http://localhost:8000/{path}"),
        ("http",  f"http://127.0.0.1:8000/{path}"),
    ]

    last_error = None
    
    if app.state.mop_scheme is not None:
        scheme = app.state.mop_scheme
        if scheme == "https":
            urls = [("https", f"https://localhost:8000/{path}"), ("https", f"https://127.0.0.1:8000/{path}")]
        else:
            urls = [("http",  f"http://localhost:8000/{path}"), ("http",  f"http://127.0.0.1:8000/{path}")]

    for scheme, url in urls:
        try:
            logging.info(f"Fetching {method} {url}")
            async with app.state.session.request(
                method,
                url,
                data=body,
                headers=headers,
                ssl=ssl_context if scheme == "https" else False,
            ) as resp:
                content = await resp.read()
                logging.info(f"Received {resp.status} {url}")
                if app.state.mop_scheme is None:
                    app.state.mop_scheme = scheme
                return {
                    "status": resp.status,
                    "body": content,
                    "headers": resp.headers,
                }
        except asyncio.CancelledError:
            raise
        except (aiohttp.ClientConnectorError, ssl.SSLError) as e:
            last_error = e
            logging.warning(f"Failed {scheme.upper()} {url}: {e}")
            continue

    logging.error(f"Failed to fetch backend: {last_error}")
    return {
        "status": 500,
        "body": b'{"status": "Failed to fetch backend", "code": 1}',
        "headers": {},
    }
    
def etag_response(func):
    async def wrapper(request: Request):
        response = await func(request)

        # Only process concrete, buffered responses
        if isinstance(response, (JSONResponse, HTMLResponse)):
            body = response.body
            if body is None:
                return response

            etag = hashlib.md5(body, usedforsecurity=False).hexdigest() # nosec

            if request.headers.get("if-none-match") == etag:
                return Response(status_code=304)

            response.headers["ETag"] = etag

        return response
    return wrapper

async def detect_encoding(encoding, body):
    loop = asyncio.get_event_loop()
    if encoding == "gzip":
        try:
            await loop.run_in_executor(None, gzip.decompress, body)
            return "gzip"
        except Exception:
            logging.warning("Failed to decompress gzip response. Calling it fakes on mop")
            return "identity"
    elif encoding == "br":
        try:
            await loop.run_in_executor(None, brotli.decompress, body) # pyright: ignore[reportAttributeAccessIssue]
            return "br"
        except Exception:
            logging.warning("Failed to decompress br response. Calling it fakes on mop")
            return "identity"
    else:
        return "identity"

@app.get("/favicon.ico")
@etag_response
async def favicon(request: Request):
    # If theres a error. they deleted my mop picture i found on google images
    try:
        return FileResponse("mop.ico")
    except FileNotFoundError:
        return PlainTextResponse("🥒 :(", status_code=404)
    except RuntimeError:
        return PlainTextResponse("🥒 :(", status_code=404)
    
@app.get("/ui/")
@etag_response
async def ui(request: Request):
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return PlainTextResponse("The server owner has not installed the UI. (Location: \"/ui/\")", status_code=404)
    
@app.get("/ui/session")
@etag_response
async def ui_session(request: Request):
    try:
        with open("session.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return PlainTextResponse("The server owner has not installed the UI. (Location: \"/ui/session\")", status_code=404)
    
@app.get("/ui/xterm")
async def xterm(request: Request):
    # try:
    with open("xterm.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())
    # except FileNotFoundError:
    #     return PlainTextResponse("The server owner has not installed the xterm client. (Location: \"/xterm\")", status_code=404)
    
    
@app.get("/client", include_in_schema=False)
@app.get("/client/{full_path:path}")
@etag_response
async def client(request: Request, full_path: str = ""):
    try:
        with open("client.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return PlainTextResponse("The server owner has not installed the html client. (Location: \"/client\")", status_code=404)
    
@app.get("/")
async def root(request: Request):
    return RedirectResponse(url="/ui/", status_code=301)

@app.get("/{full_path:path}")
async def route_to_backend(request: Request, full_path: str):
    try:
        result = await asyncio.wait_for(fetch_backend(path=full_path, method="GET", headers=dict(request.headers)), timeout=5)
    except asyncio.TimeoutError:
        logging.warning("Backend fetch timed out")
        return Response(status_code=504, content=b"Backend timeout")
    except asyncio.CancelledError:
        logging.info("Request cancelled")
        raise

    # Preserve all backend headers except hop-by-hop
    headers = {
        k: v
        for k, v in result["headers"].items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }
    
    encoding = await detect_encoding(result["headers"].get("Content-Encoding", "identity"), result["body"])
    
    headers["Content-Encoding"] = encoding
    
    headers["Content-Length"] = str(len(result["body"]))      
    
    logging.info(f"Detected encoding: {encoding}") # nosemgrep: python.fastapi.log.tainted-log-injection-stdlib-fastapi.tainted-log-injection-stdlib-fastapi

    # Send bytes exactly as received
    return Response(
        content=result["body"],
        status_code=result["status"],
        headers=headers,
        media_type=None,  # Let backend set Content-Type
    )

@app.post("/{full_path:path}")
async def route_to_backend_post(request: Request, full_path: str):
    logging.info(f"Received request for {request.method} {full_path}")
    
    body = await request.body()
    try:
        result = await asyncio.wait_for(fetch_backend(path=full_path, method="POST", body=body, headers=dict(request.headers)), timeout=5)
    except asyncio.TimeoutError:
        logging.warning("Backend fetch timed out")
        return Response(status_code=504, content=b"Backend timeout")
    except asyncio.CancelledError:
        logging.info("Request cancelled")
        raise
    
    # Preserve all backend headers except hop-by-hop
    headers = {
        k: v
        for k, v in result["headers"].items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }
    
    encoding = await detect_encoding(result["headers"].get("Content-Encoding", "identity"), result["body"])
    
    headers["Content-Encoding"] = encoding
            
    headers["Content-Length"] = str(len(result["body"]))      
    
    logging.info(f"Detected encoding: {encoding}") # nosemgrep: python.fastapi.log.tainted-log-injection-stdlib-fastapi.tainted-log-injection-stdlib-fastapi

    return Response(
        content=result["body"],
        status_code=result["status"],
        headers=headers,
    )

# We will miss you. pickle.jpeg