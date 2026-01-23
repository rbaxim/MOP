# MOP

![Python Version](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Version](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Frbaxim%2FMOP%2Frefs%2Fheads%2Fmain%2Fversion_badge.json)
![GitHub repo size](https://img.shields.io/github/repo-size/rbaxim/MOP?label=Repo%20Size)

A stdio ↔ HTTP(s) bridge that runs subprocess-backed services and exposes them via a lightweight FastAPI server.

MOP stands for *Modular Protocol* and is designed to be as modular as possible.

## Highlights

- PTY / pipe-backed subprocess sessions exposed over HTTP, SSE and WebSocket.
- Session management, plugin launcher and persistence (see ./moppy/attic, ./moppy/pepper).
- Plugin folder: ./moppy/plugins — drop-in core plugins and manifest-driven services.
- Built‑in simple Web UI: index, session.
- SSL support (use ./moppy/certs or ./moppy/ssl_certs.py to generate certs).
- Lightweight: uses FastAPI, uvicorn, aiohttp, psutil, etc. (mop.py auto-checks deps at boot).

### Quick start (Instruction kit)

> [!IMPORTANT]
> **Windows is not recommended**
> Windows support partially exists but is extremely unstable
> You may encounter random crashes and SSL issues
> The winpty module does not allow MOP to enable/disable echo
> Do not attempt to use my broken implementation of conpty with mop
> It crashes the server and needs fixing

1. Install Python (3.13 or 3.12 are recommended):
   - Debian/Ubuntu:

        ***It is recommended that you install uv and use that instead of pip and venv***

     ```bash
     sudo apt update && sudo apt install -y python3
     curl -LsSf https://astral.sh/uv/install.sh | sh
     export PATH="$HOME/.cargo/bin:$PATH"
     uv --version
     ```

     <details>
     If you want to use standard pip and uv. run this command instead:

      ```bash
      sudo apt update && sudo apt install -y python3 python3-venv python3-pip
      ```

     </details>

   - macOS (Homebrew):

        ***It is recommended that you install uv and use that instead of pip and venv***

     ```bash
     brew install python
     brew install uv
     uv --version
     ```

     <details>
     If you want to use standard pip and venv. Just execute the first command and ignore the rest.
     </details>

   - Windows:

        Install UV by running this command below

     ```powershell
     powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
     ```

     And restart your shell

        After you have installed uv. Install python

        <details>
        If you don't want to use uv. Just install python and use pip.
        </details>

        Install Python from [python.org](https://python.org) or: ```choco install python```
2. Create and activate a virtual environment:
   - All systems:

     ```bash
       uv sync
     ```

     <details>
     If you specifically want to use pip and venv. Run the commands below
        - Linux/Mac

        ```bash
        python3 -m venv .venv
        source ./.venv/bin/activate
        ```

        - Windows

        ```powershell
        python -m venv .venv
        ./.venv/Scripts/activate.ps1
        ```

    </details>

3. Run the server:

   ```bash
   uv run python mop.py -c "python test.py"
   ```

   - Use --ssl to enable TLS (requires certs in ./moppy/certs or generate them with ./moppy/ssl_certs.py).

   <details>
   If you don't want to use uv. Then run the commands below. (Assuming you enabled the venv already using the commands above)

    ```bash
    python mop.py -c "python test.py"
    ```

    </details>

4. Open the Web UI in your browser at <http://localhost:8080>.

## Usage notes

- The server exposes APIs under /mop/*. Use the Web UI for an interactive session.
- Plugins: place plugins and manifest in ./moppy/plugins. The server loads core plugins from that folder.
- Choose either to use Pipes or PTY as the method for terminal/input output. (Default: PTY)

| Method | Pros | Cons |
| --- | --- | --- |
| PTY | Full Terminal output (only returns ANSI that contain color/style data) Great for interactive sessions | Spawns an entire terminal. Slightly higher resource overhead than Pipes |
| Pipes | Efficient and fast. Great when you are with limited resources | Extremely buggy, doesn't give full TTY output, not suitable for interactive sessions |

- Use the public session to reduce strain on the server.

> [!TIP] *Would you rather spawn 100 processes for 100 clients or spawn 1 process and every client connects to it*
>
> The public process helps reduce server load by allowing multiple clients to share a single backend process instead of spawning one process per client.
>
> To disable it. See the argument table below

- **Windows Echo Issues**: The winpty module for Python does not provide a easy way to disable echoing in terminals (Mirroring stdin to stdout)

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
> MOP is intended for local, trusted networks.

### The Dangers of stealing a port

> [!WARNING]
> **Forcing/Stealing a port**: This can terminate unexpected processes
> and should be used carefully and wisely. Only use for automation.

### Pepper file

- The pepper file generated by your server serves as one of the factors for encrypting .attic files and as a salt.

> [!WARNING]
> **Destructive Key Rotation**:
> Deleting this file will immediately invalidate all existing .attic files.

## Repo & dev

- Create custom endpoints at [./moppy/mop_custom_endpoints.json](./moppy/mop_custom_endpoints.json) with any programming language.

- Add custom plugins at [./moppy/plugins](./moppy/plugins/)

### 2 API Endpoints. Same Backend

- This project provides two versions of the API

    The Basic API: ```/mop```
    The Advanced API: ```/mop/power```

- The basic endpoints

    These endpoints (```/mop/init```,```/mop/read```, ```/mop/end```, etc.) are poll-based.

- The advanced endpoints

    These endpoints located at ```/mop/power``` are advanced and slightly harder to use.

    But they are often faster than the poll-based ones

  - SSE endpoint: ```/mop/power/stream/read```

  - Websocket endpoint: ```/mop/power/sock/{key}```

### Core Plugins

Each Core plugin has its purpose

- **Attic**

    Persists sessions across server restarts

    Binds to localhost:9000.

    > [!WARNING]
    > **DO NOT EXPOSE PUBLICLY**
    > Attic is not designed to be exposed publicly.
    > It fully entrusts the requests it is being given

    Stands for *Archived Terminal and Task Image Cache*

- **Mat**

    The Web UI

    Binds to localhost:8080

    Stands for *Modular Application Terminal*

___

## Attribution

If you redistribute MOP or substantial portions of it, you must preserve the LICENSE and NOTICE files as required by Apache 2.0.
Visible credit in documentation or UI is appreciated but not required.

- See [NOTICE](NOTICE).

## License

- See [LICENSE](LICENSE).
