import asyncio
import base64
import contextlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path

from aiohttp import WSMsgType, web


STATIC_DIR = Path(__file__).parent / "static"
NOVNC_DIR = Path("/usr/share/novnc")
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)
USERNAME_RE = re.compile(r"^[^\r\n\x00]{1,256}$")
RESOLUTIONS = {(1280, 720), (1366, 768), (1600, 900), (1920, 1080)}


@dataclass
class Session:
    session_id: str
    display: int
    vnc_port: int
    created_at: float
    processes: list[asyncio.subprocess.Process] = field(default_factory=list)
    log_tasks: list[asyncio.Task] = field(default_factory=list)
    websocket_count: int = 0


class SessionManager:
    def __init__(self) -> None:
        self.sessions: dict[str, Session] = {}
        self.lock = asyncio.Lock()
        self.max_sessions = int(os.getenv("MAX_SESSIONS", "10"))
        self.max_session_seconds = int(os.getenv("MAX_SESSION_SECONDS", "28800"))
        self.display_min = 100
        self.display_max = self.display_min + self.max_sessions - 1
        self.port_min = 5900
        self.cleanup_task: asyncio.Task | None = None

    async def start(self) -> None:
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def close(self) -> None:
        if self.cleanup_task:
            self.cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.cleanup_task
        await asyncio.gather(
            *(self.stop(session_id) for session_id in list(self.sessions)),
            return_exceptions=True,
        )

    async def create(self, payload: dict) -> Session:
        connection = validate_connection(payload)

        async with self.lock:
            if len(self.sessions) >= self.max_sessions:
                raise web.HTTPServiceUnavailable(
                    text=json.dumps({"error": "Die maximale Anzahl paralleler Sitzungen ist erreicht."}),
                    content_type="application/json",
                )

            used_displays = {session.display for session in self.sessions.values()}
            display = next(
                (number for number in range(self.display_min, self.display_max + 1)
                 if number not in used_displays),
                None,
            )
            if display is None:
                raise web.HTTPServiceUnavailable(
                    text=json.dumps({"error": "Kein virtueller Bildschirm ist verfügbar."}),
                    content_type="application/json",
                )

            vnc_port = find_free_port(self.port_min, self.port_min + self.max_sessions + 20)
            session = Session(
                session_id=secrets.token_urlsafe(24),
                display=display,
                vnc_port=vnc_port,
                created_at=time.monotonic(),
            )
            self.sessions[session.session_id] = session

        try:
            await self._launch(session, connection)
            return session
        except Exception:
            await self.stop(session.session_id)
            raise

    async def stop(self, session_id: str) -> None:
        async with self.lock:
            session = self.sessions.pop(session_id, None)
        if not session:
            return

        for process in reversed(session.processes):
            if process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    process.send_signal(signal.SIGTERM)

        for process in reversed(session.processes):
            if process.returncode is None:
                try:
                    await asyncio.wait_for(process.wait(), timeout=3)
                except asyncio.TimeoutError:
                    with contextlib.suppress(ProcessLookupError):
                        process.kill()
                    await process.wait()

        for task in session.log_tasks:
            task.cancel()
        await asyncio.gather(*session.log_tasks, return_exceptions=True)

    async def _launch(self, session: Session, connection: dict) -> None:
        display_env = {**os.environ, "DISPLAY": f":{session.display}"}
        width, height = connection["resolution"]

        xvfb = await asyncio.create_subprocess_exec(
            "Xvfb",
            f":{session.display}",
            "-screen",
            "0",
            f"{width}x{height}x24",
            "-nolisten",
            "tcp",
            "-ac",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        session.processes.append(xvfb)
        session.log_tasks.append(asyncio.create_task(drain_log(xvfb.stderr, "Xvfb")))
        await asyncio.sleep(0.35)
        ensure_running(xvfb, "Der virtuelle Bildschirm konnte nicht gestartet werden.")

        openbox = await asyncio.create_subprocess_exec(
            "openbox",
            "--sm-disable",
            env=display_env,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        session.processes.append(openbox)
        session.log_tasks.append(asyncio.create_task(drain_log(openbox.stderr, "openbox")))

        x11vnc = await asyncio.create_subprocess_exec(
            "x11vnc",
            "-display",
            f":{session.display}",
            "-rfbport",
            str(session.vnc_port),
            "-localhost",
            "-forever",
            "-shared",
            "-nopw",
            "-quiet",
            "-noxdamage",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        session.processes.append(x11vnc)
        session.log_tasks.append(asyncio.create_task(drain_log(x11vnc.stderr, "x11vnc")))
        await wait_for_port("127.0.0.1", session.vnc_port, timeout=5)

        args = [
            "xfreerdp3",
            f"/v:{connection['host']}:{connection['port']}",
            f"/u:{connection['username']}",
            f"/size:{width}x{height}",
            "/bpp:24",
            "/network:auto",
            "/compression",
            "/auto-reconnect",
            "/auto-reconnect-max-retries:3",
            "/from-stdin:force",
            "/log-level:WARN",
            "/f",
            "-decorations",
            "-grab-keyboard",
        ]
        if connection["domain"]:
            args.append(f"/d:{connection['domain']}")
        if connection["admin"]:
            args.append("/admin")
        if connection["clipboard"]:
            args.append("+clipboard")
        if connection["ignore_certificate"]:
            args.append("/cert:ignore")

        freerdp = await asyncio.create_subprocess_exec(
            *args,
            env=display_env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        session.processes.append(freerdp)
        session.log_tasks.append(asyncio.create_task(drain_log(freerdp.stderr, "FreeRDP")))
        freerdp.stdin.write((connection["password"] + "\n").encode("utf-8"))
        await freerdp.stdin.drain()
        freerdp.stdin.close()
        connection["password"] = ""

        await asyncio.sleep(0.8)
        ensure_running(freerdp, "FreeRDP konnte die Verbindung nicht starten.")

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            now = time.monotonic()
            expired = []
            for session_id, session in list(self.sessions.items()):
                freerdp_exited = bool(
                    session.processes and session.processes[-1].returncode is not None
                )
                timed_out = now - session.created_at > self.max_session_seconds
                if freerdp_exited or timed_out:
                    expired.append(session_id)
            await asyncio.gather(*(self.stop(session_id) for session_id in expired))


def validate_connection(payload: dict) -> dict:
    host = str(payload.get("host", "")).strip()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not HOST_RE.fullmatch(host):
            raise web.HTTPBadRequest(
                text=json.dumps({"error": "Ungültige IP-Adresse oder ungültiger Hostname."}),
                content_type="application/json",
            )

    try:
        port = int(payload.get("port", 3389))
    except (TypeError, ValueError):
        port = 0
    if not 1 <= port <= 65535:
        raise web.HTTPBadRequest(
            text=json.dumps({"error": "Der Port muss zwischen 1 und 65535 liegen."}),
            content_type="application/json",
        )

    username = str(payload.get("username", "")).strip()
    domain = str(payload.get("domain", "")).strip()
    password = str(payload.get("password", ""))
    if not USERNAME_RE.fullmatch(username):
        raise web.HTTPBadRequest(
            text=json.dumps({"error": "Ein gültiger Benutzername ist erforderlich."}),
            content_type="application/json",
        )
    if domain and not USERNAME_RE.fullmatch(domain):
        raise web.HTTPBadRequest(
            text=json.dumps({"error": "Die Domäne enthält ungültige Zeichen."}),
            content_type="application/json",
        )
    if not password or len(password) > 1024 or "\x00" in password:
        raise web.HTTPBadRequest(
            text=json.dumps({"error": "Ein gültiges Passwort ist erforderlich."}),
            content_type="application/json",
        )

    resolution_text = str(payload.get("resolution", "1600x900"))
    try:
        resolution = tuple(int(part) for part in resolution_text.split("x", 1))
    except ValueError:
        resolution = ()
    if resolution not in RESOLUTIONS:
        raise web.HTTPBadRequest(
            text=json.dumps({"error": "Ungültige Bildschirmauflösung."}),
            content_type="application/json",
        )

    return {
        "host": host,
        "port": port,
        "username": username,
        "domain": domain,
        "password": password,
        "resolution": resolution,
        "admin": bool(payload.get("admin", False)),
        "clipboard": bool(payload.get("clipboard", True)),
        "ignore_certificate": bool(payload.get("ignoreCertificate", False)),
    }


def find_free_port(start: int, end: int) -> int:
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            try:
                candidate.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("Kein lokaler VNC-Port ist verfügbar.")


async def wait_for_port(host: str, port: int, timeout: float) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.1)
    raise RuntimeError("Der lokale Bildschirm-Proxy ist nicht erreichbar.")


def ensure_running(process: asyncio.subprocess.Process, message: str) -> None:
    if process.returncode is not None:
        raise RuntimeError(message)


async def drain_log(stream: asyncio.StreamReader | None, name: str) -> None:
    if not stream:
        return
    while line := await stream.readline():
        text = line.decode("utf-8", errors="replace").rstrip()
        if text:
            print(f"[{name}] {text}", flush=True)


def check_basic_auth(request: web.Request) -> bool:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth_header[6:], validate=True).decode("utf-8")
        username, password = decoded.split(":", 1)
    except (ValueError, UnicodeDecodeError):
        return False
    expected_user = os.environ["APP_USERNAME"]
    expected_password = os.environ["APP_PASSWORD"]
    return hmac.compare_digest(username, expected_user) and hmac.compare_digest(
        password, expected_password
    )


@web.middleware
async def security_middleware(request: web.Request, handler):
    if request.path == "/healthz":
        return await handler(request)
    if not check_basic_auth(request):
        raise web.HTTPUnauthorized(
            headers={"WWW-Authenticate": 'Basic realm="ServerManager", charset="UTF-8"'}
        )
    is_websocket = request.path.endswith("/websocket")
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} or is_websocket:
        origin = request.headers.get("Origin")
        expected = f"{request.scheme}://{request.host}"
        forwarded_proto = request.headers.get("X-Forwarded-Proto")
        if forwarded_proto:
            expected = f"{forwarded_proto}://{request.host}"
        if not origin or origin != expected:
            raise web.HTTPForbidden(
                text=json.dumps({"error": "Ungültiger Anfrageursprung."}),
                content_type="application/json",
            )
    return await handler(request)


async def index(request: web.Request) -> web.FileResponse:
    return web.FileResponse(STATIC_DIR / "index.html")


async def create_session(request: web.Request) -> web.Response:
    try:
        payload = await request.json(loads=json.loads)
    except (json.JSONDecodeError, TypeError):
        raise web.HTTPBadRequest(
            text=json.dumps({"error": "Ungültige Anfrage."}),
            content_type="application/json",
        )
    session = await request.app["sessions"].create(payload)
    return web.json_response(
        {
            "id": session.session_id,
            "websocket": f"/api/sessions/{session.session_id}/websocket",
        },
        status=201,
    )


async def delete_session(request: web.Request) -> web.Response:
    await request.app["sessions"].stop(request.match_info["session_id"])
    return web.Response(status=204)


async def websocket_proxy(request: web.Request) -> web.WebSocketResponse:
    session_id = request.match_info["session_id"]
    session = request.app["sessions"].sessions.get(session_id)
    if not session:
        raise web.HTTPNotFound()

    ws = web.WebSocketResponse(protocols=("binary",))
    await ws.prepare(request)
    session.websocket_count += 1

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", session.vnc_port)

        async def browser_to_vnc() -> None:
            async for message in ws:
                if message.type == WSMsgType.BINARY:
                    writer.write(message.data)
                    await writer.drain()
                elif message.type == WSMsgType.TEXT:
                    writer.write(message.data.encode("latin-1"))
                    await writer.drain()
                elif message.type in {WSMsgType.CLOSE, WSMsgType.ERROR}:
                    break

        async def vnc_to_browser() -> None:
            while data := await reader.read(65536):
                await ws.send_bytes(data)

        tasks = [
            asyncio.create_task(browser_to_vnc()),
            asyncio.create_task(vnc_to_browser()),
        ]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*done, *pending, return_exceptions=True)
        writer.close()
        await writer.wait_closed()
    finally:
        session.websocket_count = max(0, session.websocket_count - 1)
        await ws.close()
    return ws


async def health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def on_startup(app: web.Application) -> None:
    await app["sessions"].start()


async def on_cleanup(app: web.Application) -> None:
    await app["sessions"].close()


def create_app() -> web.Application:
    if not os.getenv("APP_USERNAME") or not os.getenv("APP_PASSWORD"):
        raise RuntimeError("APP_USERNAME und APP_PASSWORD müssen gesetzt sein.")

    app = web.Application(
        middlewares=[security_middleware],
        client_max_size=16 * 1024,
    )
    app["sessions"] = SessionManager()
    app.router.add_get("/", index)
    app.router.add_post("/api/sessions", create_session)
    app.router.add_delete("/api/sessions/{session_id}", delete_session)
    app.router.add_get("/api/sessions/{session_id}/websocket", websocket_proxy)
    app.router.add_get("/healthz", health)
    app.router.add_static("/novnc/", NOVNC_DIR, show_index=False)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=8080, access_log=None)
