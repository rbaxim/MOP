"""
Modular Application Terminal
"""
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse, PlainTextResponse, JSONResponse, RedirectResponse, Response
import hashlib
import aiohttp
import ssl
import logging
import brotlicffi as brotli
import gzip
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.timeout = aiohttp.ClientTimeout(total=10)
    app.state.session = aiohttp.ClientSession(timeout=app.state.timeout)
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


async def fetch_backend(path: str, method="GET", body=None, headers=None):
    ssl_context = make_ssl_context()
    urls = [
        ("https", f"https://localhost:8000/{path}"),
        ("https", f"https://127.0.0.1:8000/{path}"),
        ("http",  f"http://localhost:8000/{path}"),
        ("http",  f"http://127.0.0.1:8000/{path}"),
    ]

    last_error = None

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
                return {
                    "status": resp.status,
                    "body": content,
                    "headers": resp.headers,
                }
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

            etag = hashlib.md5(body).hexdigest()

            if request.headers.get("if-none-match") == etag:
                return Response(status_code=304)

            response.headers["ETag"] = etag

        return response
    return wrapper

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
        with open("index.html", "r") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return PlainTextResponse("The server owner has not installed the UI. (Location: \"/ui/\")", status_code=404)
    
@app.get("/ui/session")
@etag_response
async def ui_session(request: Request):
    try:
        with open("session.html", "r") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return PlainTextResponse("The server owner has not installed the UI. (Location: \"/ui/session\")", status_code=404)
    
@app.get("/client", include_in_schema=False)
@app.get("/client/{full_path:path}")
@etag_response
async def client(request: Request, full_path: str = ""):
    try:
        with open("client.html", "r") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return PlainTextResponse("The server owner has not installed the html client. (Location: \"/client\")", status_code=404)
    
@app.get("/")
async def root(request: Request):
    return RedirectResponse(url="/ui/", status_code=301)

@app.get("/{full_path:path}")
async def route_to_backend(request: Request, full_path: str):
    result = await fetch_backend(path=full_path, method="GET", headers=dict(request.headers))

    # Preserve all backend headers except hop-by-hop
    headers = {
        k: v
        for k, v in result["headers"].items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }
    
    encoding = result["headers"].get("Content-Encoding", "identity")
    
    if encoding == "gzip":
        try:
            gzip.decompress(result["body"])
            headers["Content-Encoding"] = "gzip"
        except Exception:
            logging.warning("Failed to decompress gzip response. Calling it fakes on mop")
            headers["Content-Encoding"] = "identity"
    elif encoding == "br":
        try:
            brotli.decompress(result["body"])
            headers["Content-Encoding"] = "br"
        except Exception:
            logging.warning("Failed to decompress br response. Calling it fakes on mop")
            headers["Content-Encoding"] = "identity"
    else:
        headers["Content-Encoding"] = "identity"
            
    headers["Content-Length"] = str(len(result["body"]))      
    
    logging.info(f"Detected encoding: {encoding}")

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

    result = await fetch_backend(
        path=full_path,
        method="POST",
        body=body,
        headers=dict(request.headers),
    )
    
    # Preserve all backend headers except hop-by-hop
    headers = {
        k: v
        for k, v in result["headers"].items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }
    
    encoding = result["headers"].get("Content-Encoding", "identity")
    
    if encoding == "gzip":
        try:
            gzip.decompress(result["body"])
            headers["Content-Encoding"] = "gzip"
        except Exception:
            logging.warning("Failed to decompress gzip response. Calling it fakes on mop")
            headers["Content-Encoding"] = "identity"
    elif encoding == "br":
        try:
            brotli.decompress(result["body"])
            headers["Content-Encoding"] = "br"
        except Exception:
            logging.warning("Failed to decompress br response. Calling it fakes on mop")
            headers["Content-Encoding"] = "identity"
    else:
        headers["Content-Encoding"] = "identity"
            
    headers["Content-Length"] = str(len(result["body"]))      
    
    logging.info(f"Detected encoding: {encoding}")

    return Response(
        content=result["body"],
        status_code=result["status"],
        headers=headers,
    )

# We will miss you. pickle.jpeg