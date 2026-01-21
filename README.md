# MOP

![Python Version](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green?link=https%3A%2F%2Fgithub.com%2Frbaxim%2FMOP%3Ftab%3DMIT-1-ov-file)
![Version](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Frbaxim%2FMOP%2Frefs%2Fheads%2Fmain%2Fversion_badge.json)
![GitHub repo size](https://img.shields.io/github/repo-size/rbaxim/MOP?label=Repo%20Size)

A stdio ↔ HTTP(s) bridge: runs subprocess-backed services and exposes them via a small FastAPI server.

MOP stands for ```Modular Protocol``` as it is designed to be as modular as possible.

## Highlights

- PTY / pipe-backed subprocess sessions exposed over HTTP, SSE and WebSocket.
- Session management, plugin launcher and persistence (see ./moppy/attic, ./moppy/pepper).
- Plugin folder: ./moppy/plugins — drop-in core plugins and manifest-driven services.
- Built‑in simple Web UI: index, session.
- SSL support (use ./moppy/certs or ./moppy/ssl_certs.py to generate certs).
- Lightweight: uses FastAPI, uvicorn, aiohttp, psutil, etc. (mop.py auto-checks deps at boot).

### Quick start (Instruction kit)

1. Install Python (3.13 or 3.12 are recommended), venv and pip:
   - Debian/Ubuntu:

     ```bash
     sudo apt update && sudo apt install -y python3 python3-venv python3-pip
     ```

   - macOS (Homebrew):

     ```bash
     brew install python
     ```

   - Windows:
     Install from [python.org](https://python.org) or: ```choco install python```
2. Create and activate a virtual environment:
   - Windows (PowerShell):

    ```powershell
     python -m venv .venv
     .venv\Scripts\Activate.ps1
    ```

   - macOS / Linux:

    ```bash
     python3 -m venv .venv
     source .venv/bin/activate
    ```

3. (Optional) Upgrade pip:
   python -m pip install -U pip
4. Run the server:

   ```bash
   python mop.py -c "python test.py"
   ```

   - Use --ssl to enable TLS (requires certs in ./moppy/certs or generate them with ./moppy/ssl_certs.py).
5. Open the Web UI in your browser at localhost:8080.

## Usage notes

- The server exposes APIs under /mop/*. Use the Web UI for an interactive session.
- Plugins: place plugins and manifest in ./moppy/plugins. The server loads core plugins from that folder.
- Choose either to use Piping or PTY as the method for getting terminal output and pushing terminal input. (Default is pty)

| Method | Pros | Cons |
| --- | --- | --- |
| PTY | Full Terminal output (only returns ANSI that contain color/style data) Great for interactive sessions | Spawns a entire terminal. Much slower than Piping |
| Pipes | Efficent and fast. Great when you are with limited resources | Extremely buggy, doesn't give full tty output, and does not work for interactive sessions |

- Use the public session to reduce strain on the server. *Would you rather spawn 100 processes for 100 clients or spawn 1 process and every client connects to it*

- **Windows Echo Issues**: The winpty module for python does not provide a easy way to disable echoing in terminals (Mirroring stdin to stdout)

### Arguments

| Argument | Type | Default | Is Required | Description |
| --- | --- | --- | --- | --- |
| ```-p```, ```--port``` | Integer | 8000 | No | Sets the port for MOP to bind to |
| ```--host``` | String | 127.0.0.1 | No | Sets the interface for MOP to bind to |
| ```-c```, ```--cmd``` | String | None | Yes | The command for MOP to wrap with either pty or pipes [See this warning](#possible-rce) |
| ```-r```, ```--rate-limit``` | Flag | False | No | Enables rate limits for possible abusive endpoints (```/mop/write```, ```/mop/init```, etc.) |
| ```--cwd``` | String | Current working directory where MOP was started | No | Sets the CWD for the sessions to run in |
| ```--ssl``` | Flag | False | No | Enables SSL |
| ```-w```, ```--workers``` | Integer | 1 | No | Sets the amount of FastAPI workers to spawn |
| ```--force-port``` | Flag | False | No | Disables interactive prompts when another process is bound to the port FastAPI wants to use and kills the process using the port without warning [See this warning](#the-dangers-of-stealing-a-port) |
| ```--no-pub-process``` | Flag | False | No | Prevents automatic creation of a public session |

## Security and Warnings

### Possible RCE

> [!WARNING]
> **Remote Code Execution Risk**: MOP bridges stdin/stdout to HTTP(s).
> Exposing this server to the open internet without a firewall or
> authentication is extremely dangerous.

### The Dangers of stealing a port

> [!WARNING]
> **Forcing/Stealing a port**: This can terminate unexpected processes
> and should be used carefully and wisely. Only use for automation.

## Repo & dev

- This project aims to be mypy-compliant. Run static checks:

  ```bash
  mypy .
  ```

- Create custom endpoints at [./moppy/mop_custom_endpoints.json](./moppy/mop_custom_endpoints.json) with any programming language.

- Add custom plugins at [./moppy/plugins](./moppy/plugins/)

### 2 API Endpoints. Same Backend

- This project provides 2 verisons of the api

    The basic one (```/mop```) and the advanced one (```/mop/power```)

- The basic endpoints

    These endpoints (```/mop/init```,```/mop/read```, ```/mop/end```, etc.) are poll-based.

- The advnaced endpoints

    These endpoints located at ```/mop/power``` are advanced and slightly harder to use.

    But they are often more faster than the poll-based ones

    - SSE endpoint: ```/mop/power/stream/read```

    - Websocket endpoint: ```/mop/power/sock/{key}```

### Core Plugins

Each Core plugin has its purpose

- **Attic**

    Persisting sessions across Server restarts

    Binds to localhost:9000.

    > [!WARNING]
    > DO NOT EXPOSE PUBLICLY

    Stands for *Archived Terminal and Task Image Cache*

- **Mat**

    The web UI

    Binds to localhost:8080

    Stands for *Modular Application Terminal*

___

License

- See [LICENSE](LICENSE).
