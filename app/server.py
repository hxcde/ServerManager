import asyncio
import base64
import contextlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import pyotp
import qrcode
from aiohttp import WSMsgType, web
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from qrcode.image.svg import SvgPathImage
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)

from rdp import SessionManager, validate_connection
from storage import Database


STATIC_DIR = Path(__file__).parent / "static"
NOVNC_DIR = Path("/usr/share/novnc")
AUTH_COOKIE = "servermanager_session"
APP_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
PUBLIC_PATHS = {
    "/healthz",
    "/login",
    "/api/login/password",
    "/api/login/passkey/options",
    "/api/login/passkey/verify",
}
LOGGER = logging.getLogger("servermanager")


@dataclass
class AuthSession:
    session_id: str
    csrf_token: str
    user_id: int
    username: str
    display_name: str
    is_admin: bool
    expires_at: float


@dataclass
class WebAuthnCeremony:
    user_id: int
    challenge: bytes
    expires_at: float
    name: str = ""


class AuthManager:
    def __init__(self) -> None:
        self.sessions: dict[str, AuthSession] = {}
        self.failed_logins: dict[str, list[float]] = {}
        self.session_seconds = int(os.getenv("AUTH_SESSION_SECONDS", "28800"))
        self.login_window_seconds = 300
        self.max_login_attempts = 5

    def create(self, user: sqlite3.Row) -> AuthSession:
        session = AuthSession(
            session_id=secrets.token_urlsafe(32),
            csrf_token=secrets.token_urlsafe(32),
            user_id=user["id"],
            username=user["username"],
            display_name=user["display_name"],
            is_admin=bool(user["is_admin"]),
            expires_at=time.time() + self.session_seconds,
        )
        self.sessions[session.session_id] = session
        return session

    def get(self, session_id: str | None) -> AuthSession | None:
        if not session_id:
            return None
        session = self.sessions.get(session_id)
        if not session:
            return None
        if session.expires_at <= time.time():
            self.sessions.pop(session_id, None)
            return None
        return session

    def delete(self, session_id: str | None) -> None:
        if session_id:
            self.sessions.pop(session_id, None)

    def delete_user_sessions(self, user_id: int) -> list[str]:
        deleted = []
        for session_id, session in list(self.sessions.items()):
            if session.user_id == user_id:
                self.sessions.pop(session_id, None)
                deleted.append(session_id)
        return deleted

    def login_allowed(self, client_ip: str) -> bool:
        cutoff = time.time() - self.login_window_seconds
        attempts = [stamp for stamp in self.failed_logins.get(client_ip, []) if stamp > cutoff]
        self.failed_logins[client_ip] = attempts
        return len(attempts) < self.max_login_attempts

    def record_failure(self, client_ip: str) -> None:
        self.failed_logins.setdefault(client_ip, []).append(time.time())

    def clear_failures(self, client_ip: str) -> None:
        self.failed_logins.pop(client_ip, None)


def env_flag(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).lower() in {"1", "true", "yes"}


def request_origin(request: web.Request) -> str:
    public_url = os.getenv("PUBLIC_URL", "").strip().rstrip("/")
    if public_url:
        return public_url
    if env_flag("TRUST_PROXY_HEADERS"):
        forwarded_proto = request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip()
        forwarded_host = request.headers.get("X-Forwarded-Host", "").split(",")[0].strip()
    else:
        forwarded_proto = ""
        forwarded_host = ""
    return f"{forwarded_proto or request.scheme}://{forwarded_host or request.host}"


def client_ip(request: web.Request) -> str:
    if env_flag("TRUST_PROXY_HEADERS"):
        forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return request.remote or "unknown"


def secure_cookie(request: web.Request) -> bool:
    return request_origin(request).startswith("https://")


def webauthn_config(request: web.Request) -> tuple[str, str]:
    origin = os.getenv("WEBAUTHN_ORIGIN", "").strip().rstrip("/") or request_origin(request)
    rp_id = os.getenv("WEBAUTHN_RP_ID", "").strip() or (urlparse(origin).hostname or "")
    if not rp_id:
        raise RuntimeError("WEBAUTHN_RP_ID konnte nicht ermittelt werden.")
    return origin, rp_id


def json_error(message: str, status: int) -> web.Response:
    return web.json_response({"error": message}, status=status)


async def json_body(request: web.Request) -> dict:
    try:
        value = await request.json(loads=json.loads)
    except (json.JSONDecodeError, TypeError):
        raise web.HTTPBadRequest(
            text=json.dumps({"error": "Ungültige Anfrage."}),
            content_type="application/json",
        )
    if not isinstance(value, dict):
        raise web.HTTPBadRequest(
            text=json.dumps({"error": "Ungültige Anfrage."}),
            content_type="application/json",
        )
    return value


def validate_app_password(password: str) -> None:
    if not 12 <= len(password) <= 256 or "\x00" in password:
        raise web.HTTPBadRequest(
            text=json.dumps({"error": "Das Passwort muss 12 bis 256 Zeichen lang sein."}),
            content_type="application/json",
        )


def verify_password(hasher: PasswordHasher, password_hash: str, password: str) -> bool:
    try:
        return hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def set_auth_cookie(request: web.Request, response: web.StreamResponse, session: AuthSession) -> None:
    response.set_cookie(
        AUTH_COOKIE,
        session.session_id,
        max_age=request.app["auth"].session_seconds,
        httponly=True,
        secure=secure_cookie(request),
        samesite="Strict",
        path="/",
    )


def prune_ceremonies(ceremonies: dict[str, WebAuthnCeremony]) -> None:
    now = time.time()
    for flow_id, ceremony in list(ceremonies.items()):
        if ceremony.expires_at <= now:
            ceremonies.pop(flow_id, None)


def require_admin(request: web.Request) -> None:
    if not request["auth"].is_admin:
        raise web.HTTPForbidden(
            text=json.dumps({"error": "Administratorrechte erforderlich."}),
            content_type="application/json",
        )


def render_page(request: web.Request, filename: str) -> web.Response:
    html = (STATIC_DIR / filename).read_text(encoding="utf-8")
    html = html.replace("__CSRF_TOKEN__", request["auth"].csrf_token)
    return web.Response(
        text=html,
        content_type="text/html",
        headers={"Cache-Control": "no-store"},
    )


@web.middleware
async def api_error_middleware(request: web.Request, handler):
    try:
        return await handler(request)
    except web.HTTPException:
        raise
    except sqlite3.IntegrityError:
        return json_error("Dieser Eintrag ist bereits vorhanden.", 409)
    except (RuntimeError, FileNotFoundError, OSError) as error:
        LOGGER.exception("Gateway operation failed")
        if request.path.startswith("/api/"):
            return json_error(str(error).strip() or "Die Aktion ist fehlgeschlagen.", 500)
        raise
    except Exception:
        LOGGER.exception("Unexpected request failure")
        if request.path.startswith("/api/"):
            return json_error("Interner Serverfehler. Bitte die Container-Logs prüfen.", 500)
        raise


@web.middleware
async def security_middleware(request: web.Request, handler):
    is_public = request.path in PUBLIC_PATHS
    if is_public:
        if request.method == "POST":
            origin = request.headers.get("Origin")
            if not origin or origin != request_origin(request):
                return json_error("Ungültiger Anfrageursprung.", 403)
        return await handler(request)

    auth = request.app["auth"].get(request.cookies.get(AUTH_COOKIE))
    user = request.app["db"].get_user(auth.user_id) if auth else None
    if not auth or not user or not user["enabled"]:
        if auth:
            request.app["auth"].delete(auth.session_id)
        if request.method == "GET" and not request.path.startswith("/api/"):
            raise web.HTTPFound("/login")
        return json_error("Die Anmeldung ist abgelaufen.", 401)

    auth.username = user["username"]
    auth.display_name = user["display_name"]
    auth.is_admin = bool(user["is_admin"])
    request["auth"] = auth

    is_websocket = request.path.endswith("/websocket")
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} or is_websocket:
        origin = request.headers.get("Origin")
        if not origin or origin != request_origin(request):
            return json_error("Ungültiger Anfrageursprung.", 403)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        token = request.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(token, auth.csrf_token):
            return json_error("Ungültiges Sicherheitstoken.", 403)
    return await handler(request)


async def login_page(request: web.Request) -> web.StreamResponse:
    if request.app["auth"].get(request.cookies.get(AUTH_COOKIE)):
        raise web.HTTPFound("/")
    return web.FileResponse(
        STATIC_DIR / "login.html",
        headers={"Cache-Control": "no-store"},
    )


async def password_login(request: web.Request) -> web.Response:
    remote = client_ip(request)
    if not request.app["auth"].login_allowed(remote):
        return json_error("Zu viele Fehlversuche. Bitte in einigen Minuten erneut versuchen.", 429)

    payload = await json_body(request)
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    totp_code = str(payload.get("totp", "")).replace(" ", "")
    user = request.app["db"].get_user_by_username(username)

    password_hash = user["password_hash"] if user else request.app["dummy_password_hash"]
    valid = verify_password(request.app["password_hasher"], password_hash, password)
    if not user or not user["enabled"] or not valid:
        request.app["auth"].record_failure(remote)
        return json_error("Benutzername oder Passwort ist nicht korrekt.", 401)

    if user["totp_enabled"]:
        if not totp_code:
            return web.json_response({"totpRequired": True}, status=202)
        if not pyotp.TOTP(user["totp_secret"]).verify(totp_code, valid_window=1):
            request.app["auth"].record_failure(remote)
            return json_error("Der TOTP-Code ist nicht korrekt.", 401)

    if request.app["password_hasher"].check_needs_rehash(user["password_hash"]):
        request.app["db"].update_password(user["id"], password)
        user = request.app["db"].get_user(user["id"])

    request.app["auth"].clear_failures(remote)
    session = request.app["auth"].create(user)
    response = web.json_response({"ok": True})
    set_auth_cookie(request, response, session)
    return response


async def passkey_login_options(request: web.Request) -> web.Response:
    remote = client_ip(request)
    if not request.app["auth"].login_allowed(remote):
        return json_error("Zu viele Fehlversuche. Bitte in einigen Minuten erneut versuchen.", 429)

    payload = await json_body(request)
    username = str(payload.get("username", "")).strip()
    user = request.app["db"].get_user_by_username(username)
    if not user or not user["enabled"]:
        request.app["auth"].record_failure(remote)
        return json_error("Für diesen Benutzer ist kein Passkey verfügbar.", 400)

    descriptors = request.app["db"].passkey_descriptors(user["id"])
    if not descriptors:
        return json_error("Für diesen Benutzer ist kein Passkey verfügbar.", 400)

    origin, rp_id = webauthn_config(request)
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=bytes(row["credential_id"]))
            for row in descriptors
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    flow_id = secrets.token_urlsafe(24)
    prune_ceremonies(request.app["login_ceremonies"])
    request.app["login_ceremonies"][flow_id] = WebAuthnCeremony(
        user_id=user["id"],
        challenge=options.challenge,
        expires_at=time.time() + 300,
    )
    return web.json_response(
        {
            "flowId": flow_id,
            "publicKey": json.loads(options_to_json(options)),
            "origin": origin,
        }
    )


async def passkey_login_verify(request: web.Request) -> web.Response:
    payload = await json_body(request)
    flow_id = str(payload.get("flowId", ""))
    credential = payload.get("credential")
    ceremony = request.app["login_ceremonies"].pop(flow_id, None)
    if not ceremony or ceremony.expires_at <= time.time() or not isinstance(credential, dict):
        return json_error("Die Passkey-Anfrage ist abgelaufen.", 400)

    user = request.app["db"].get_user(ceremony.user_id)
    if not user or not user["enabled"]:
        return json_error("Die Anmeldung ist nicht möglich.", 401)

    try:
        credential_id = base64url_to_bytes(str(credential.get("id", "")))
    except ValueError:
        return json_error("Ungültige Passkey-Antwort.", 400)
    passkey = request.app["db"].get_passkey(user["id"], credential_id)
    if not passkey:
        return json_error("Der Passkey ist nicht registriert.", 401)

    origin, rp_id = webauthn_config(request)
    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=ceremony.challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            credential_public_key=bytes(passkey["public_key"]),
            credential_current_sign_count=passkey["sign_count"],
            require_user_verification=True,
        )
    except InvalidAuthenticationResponse:
        request.app["auth"].record_failure(client_ip(request))
        return json_error("Die Passkey-Anmeldung konnte nicht bestätigt werden.", 401)
    request.app["db"].update_passkey_counter(passkey["id"], verification.new_sign_count)
    request.app["auth"].clear_failures(client_ip(request))
    session = request.app["auth"].create(user)
    response = web.json_response({"ok": True})
    set_auth_cookie(request, response, session)
    return response


async def logout(request: web.Request) -> web.Response:
    await request.app["sessions"].stop_owned(request["auth"].session_id)
    request.app["auth"].delete(request.cookies.get(AUTH_COOKIE))
    response = web.json_response({"ok": True})
    response.del_cookie(AUTH_COOKIE, path="/")
    return response


async def index(request: web.Request) -> web.Response:
    return render_page(request, "index.html")


async def account_page(request: web.Request) -> web.Response:
    return render_page(request, "account.html")


async def admin_page(request: web.Request) -> web.Response:
    require_admin(request)
    return render_page(request, "admin.html")


async def me(request: web.Request) -> web.Response:
    user = request.app["db"].public_user(request["auth"].user_id)
    user["passkeys"] = request.app["db"].list_passkeys(request["auth"].user_id)
    return web.json_response(user)


async def change_password(request: web.Request) -> web.Response:
    payload = await json_body(request)
    current_password = str(payload.get("currentPassword", ""))
    new_password = str(payload.get("newPassword", ""))
    validate_app_password(new_password)
    user = request.app["db"].get_user(request["auth"].user_id)
    if not verify_password(request.app["password_hasher"], user["password_hash"], current_password):
        return json_error("Das aktuelle Passwort ist nicht korrekt.", 400)
    request.app["db"].update_password(user["id"], new_password)
    return web.json_response({"ok": True})


async def totp_setup(request: web.Request) -> web.Response:
    user = request.app["db"].get_user(request["auth"].user_id)
    if user["totp_enabled"]:
        return json_error("TOTP ist bereits eingerichtet.", 400)
    secret = pyotp.random_base32()
    issuer = os.getenv("TOTP_ISSUER", "ServerManager")
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=user["username"],
        issuer_name=issuer,
    )
    qr = qrcode.make(uri, image_factory=SvgPathImage)
    output = io.BytesIO()
    qr.save(output)
    qr_data = base64.b64encode(output.getvalue()).decode("ascii")
    request.app["totp_pending"][request["auth"].session_id] = {
        "secret": secret,
        "expiresAt": time.time() + 600,
    }
    return web.json_response(
        {
            "secret": secret,
            "qrCode": f"data:image/svg+xml;base64,{qr_data}",
        }
    )


async def totp_enable(request: web.Request) -> web.Response:
    payload = await json_body(request)
    code = str(payload.get("code", "")).replace(" ", "")
    pending = request.app["totp_pending"].get(request["auth"].session_id)
    if not pending or pending["expiresAt"] <= time.time():
        request.app["totp_pending"].pop(request["auth"].session_id, None)
        return json_error("Die TOTP-Einrichtung ist abgelaufen.", 400)
    if not pyotp.TOTP(pending["secret"]).verify(code, valid_window=1):
        return json_error("Der TOTP-Code ist nicht korrekt.", 400)
    request.app["totp_pending"].pop(request["auth"].session_id, None)
    request.app["db"].set_totp(request["auth"].user_id, pending["secret"], True)
    return web.json_response({"ok": True})


async def totp_disable(request: web.Request) -> web.Response:
    payload = await json_body(request)
    code = str(payload.get("code", "")).replace(" ", "")
    user = request.app["db"].get_user(request["auth"].user_id)
    if not user["totp_enabled"]:
        return web.json_response({"ok": True})
    if not pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
        return json_error("Der TOTP-Code ist nicht korrekt.", 400)
    request.app["db"].set_totp(user["id"], None, False)
    return web.json_response({"ok": True})


async def passkey_register_options(request: web.Request) -> web.Response:
    payload = await json_body(request)
    name = str(payload.get("name", "")).strip()
    if not 1 <= len(name) <= 80:
        return json_error("Bitte einen Namen für den Passkey angeben.", 400)

    user = request.app["db"].get_user(request["auth"].user_id)
    existing = request.app["db"].passkey_descriptors(user["id"])
    origin, rp_id = webauthn_config(request)
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=os.getenv("WEBAUTHN_RP_NAME", "ServerManager"),
        user_id=user["id"].to_bytes(8, "big"),
        user_name=user["username"],
        user_display_name=user["display_name"],
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=bytes(row["credential_id"]))
            for row in existing
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    flow_id = secrets.token_urlsafe(24)
    prune_ceremonies(request.app["registration_ceremonies"])
    request.app["registration_ceremonies"][flow_id] = WebAuthnCeremony(
        user_id=user["id"],
        challenge=options.challenge,
        expires_at=time.time() + 300,
        name=name,
    )
    return web.json_response(
        {
            "flowId": flow_id,
            "publicKey": json.loads(options_to_json(options)),
            "origin": origin,
        }
    )


async def passkey_register_verify(request: web.Request) -> web.Response:
    payload = await json_body(request)
    flow_id = str(payload.get("flowId", ""))
    credential = payload.get("credential")
    ceremony = request.app["registration_ceremonies"].pop(flow_id, None)
    if (
        not ceremony
        or ceremony.user_id != request["auth"].user_id
        or ceremony.expires_at <= time.time()
        or not isinstance(credential, dict)
    ):
        return json_error("Die Passkey-Anfrage ist abgelaufen.", 400)

    origin, rp_id = webauthn_config(request)
    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=ceremony.challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            require_user_verification=True,
        )
    except InvalidRegistrationResponse:
        return json_error("Der Passkey konnte nicht bestätigt werden.", 400)
    transports = credential.get("response", {}).get("transports", [])
    if not isinstance(transports, list):
        transports = []
    passkey = request.app["db"].add_passkey(
        user_id=ceremony.user_id,
        name=ceremony.name,
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        transports=[str(item) for item in transports],
    )
    return web.json_response(passkey, status=201)


async def delete_passkey(request: web.Request) -> web.Response:
    deleted = request.app["db"].delete_passkey(
        request["auth"].user_id,
        int(request.match_info["passkey_id"]),
    )
    if not deleted:
        raise web.HTTPNotFound()
    return web.Response(status=204)


async def domains(request: web.Request) -> web.Response:
    return web.json_response(request.app["db"].list_domains())


async def admin_users(request: web.Request) -> web.Response:
    require_admin(request)
    if request.method == "GET":
        return web.json_response(request.app["db"].list_users())

    payload = await json_body(request)
    username = str(payload.get("username", "")).strip()
    display_name = str(payload.get("displayName", "")).strip() or username
    password = str(payload.get("password", ""))
    if not APP_USERNAME_RE.fullmatch(username):
        return json_error("Der Benutzername enthält ungültige Zeichen.", 400)
    if not 1 <= len(display_name) <= 80:
        return json_error("Der Anzeigename muss 1 bis 80 Zeichen lang sein.", 400)
    validate_app_password(password)
    user = request.app["db"].create_user(
        username=username,
        display_name=display_name,
        password=password,
        is_admin=bool(payload.get("isAdmin", False)),
    )
    return web.json_response(user, status=201)


async def admin_user(request: web.Request) -> web.Response:
    require_admin(request)
    user_id = int(request.match_info["user_id"])
    target = request.app["db"].get_user(user_id)
    if not target:
        raise web.HTTPNotFound()

    if request.method == "DELETE":
        if user_id == request["auth"].user_id:
            return json_error("Das eigene Administratorkonto kann nicht gelöscht werden.", 400)
        if target["enabled"] and target["is_admin"] and request.app["db"].enabled_admin_count() <= 1:
            return json_error("Der letzte aktive Administrator kann nicht gelöscht werden.", 400)
        revoked_sessions = request.app["auth"].delete_user_sessions(user_id)
        await asyncio.gather(
            *(request.app["sessions"].stop_owned(session_id) for session_id in revoked_sessions)
        )
        request.app["db"].delete_user(user_id)
        return web.Response(status=204)

    payload = await json_body(request)
    display_name = str(payload.get("displayName", target["display_name"])).strip()
    enabled = bool(payload.get("enabled", target["enabled"]))
    is_admin = bool(payload.get("isAdmin", target["is_admin"]))
    password = str(payload.get("password", "")) or None
    if not 1 <= len(display_name) <= 80:
        return json_error("Der Anzeigename muss 1 bis 80 Zeichen lang sein.", 400)
    if password:
        validate_app_password(password)
    if user_id == request["auth"].user_id and (not enabled or not is_admin):
        return json_error("Das eigene Administratorkonto muss aktiv und Administrator bleiben.", 400)
    if (
        target["enabled"]
        and target["is_admin"]
        and (not enabled or not is_admin)
        and request.app["db"].enabled_admin_count() <= 1
    ):
        return json_error("Der letzte aktive Administrator kann nicht deaktiviert werden.", 400)
    user = request.app["db"].update_user(
        user_id=user_id,
        display_name=display_name,
        enabled=enabled,
        is_admin=is_admin,
        password=password,
    )
    if not enabled or (password and user_id != request["auth"].user_id):
        revoked_sessions = request.app["auth"].delete_user_sessions(user_id)
        await asyncio.gather(
            *(request.app["sessions"].stop_owned(session_id) for session_id in revoked_sessions)
        )
    return web.json_response(user)


async def admin_domains(request: web.Request) -> web.Response:
    require_admin(request)
    if request.method == "GET":
        return web.json_response(request.app["db"].list_domains())
    payload = await json_body(request)
    name = str(payload.get("name", "")).strip()
    if not DOMAIN_RE.fullmatch(name):
        return json_error("Die Domäne enthält ungültige Zeichen.", 400)
    return web.json_response(request.app["db"].add_domain(name), status=201)


async def delete_domain(request: web.Request) -> web.Response:
    require_admin(request)
    if not request.app["db"].delete_domain(int(request.match_info["domain_id"])):
        raise web.HTTPNotFound()
    return web.Response(status=204)


async def history(request: web.Request) -> web.Response:
    return web.json_response(request.app["db"].list_history(request["auth"].user_id))


async def delete_history(request: web.Request) -> web.Response:
    deleted = request.app["db"].delete_history(
        request["auth"].user_id,
        int(request.match_info["history_id"]),
    )
    if not deleted:
        raise web.HTTPNotFound()
    return web.Response(status=204)


async def create_session(request: web.Request) -> web.Response:
    payload = await json_body(request)
    connection = validate_connection(payload)
    if not request.app["db"].domain_exists(connection["domain"]):
        return json_error("Die ausgewählte Domäne ist nicht freigegeben.", 400)
    session = await request.app["sessions"].create(payload, request["auth"].session_id)
    payload["password"] = ""
    connection["password"] = ""
    request.app["db"].save_history(request["auth"].user_id, connection)
    return web.json_response(
        {
            "id": session.session_id,
            "websocket": f"/api/sessions/{session.session_id}/websocket",
        },
        status=201,
    )


async def delete_session(request: web.Request) -> web.Response:
    session_id = request.match_info["session_id"]
    session = request.app["sessions"].sessions.get(session_id)
    if session and session.owner_id != request["auth"].session_id:
        raise web.HTTPNotFound()
    await request.app["sessions"].stop(session_id)
    return web.Response(status=204)


async def websocket_proxy(request: web.Request) -> web.WebSocketResponse:
    session_id = request.match_info["session_id"]
    session = request.app["sessions"].sessions.get(session_id)
    if not session or session.owner_id != request["auth"].session_id:
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
    app["db"].close()


def create_app() -> web.Application:
    bootstrap_username = os.getenv("APP_USERNAME", "").strip()
    bootstrap_password = os.getenv("APP_PASSWORD", "")
    if not bootstrap_username or not bootstrap_password:
        raise RuntimeError("APP_USERNAME und APP_PASSWORD müssen gesetzt sein.")

    password_hasher = PasswordHasher()
    database = Database(
        path=os.getenv("DATABASE_PATH", "/data/servermanager.db"),
        password_hasher=password_hasher,
        bootstrap_username=bootstrap_username,
        bootstrap_password=bootstrap_password,
    )
    app = web.Application(
        middlewares=[api_error_middleware, security_middleware],
        client_max_size=64 * 1024,
    )
    app["sessions"] = SessionManager()
    app["auth"] = AuthManager()
    app["db"] = database
    app["password_hasher"] = password_hasher
    app["dummy_password_hash"] = password_hasher.hash(secrets.token_urlsafe(32))
    app["login_ceremonies"] = {}
    app["registration_ceremonies"] = {}
    app["totp_pending"] = {}

    app.router.add_get("/", index)
    app.router.add_get("/login", login_page)
    app.router.add_post("/api/login/password", password_login)
    app.router.add_post("/api/login/passkey/options", passkey_login_options)
    app.router.add_post("/api/login/passkey/verify", passkey_login_verify)
    app.router.add_post("/logout", logout)

    app.router.add_get("/account", account_page)
    app.router.add_get("/admin", admin_page)
    app.router.add_get("/api/me", me)
    app.router.add_post("/api/account/password", change_password)
    app.router.add_post("/api/account/totp/setup", totp_setup)
    app.router.add_post("/api/account/totp/enable", totp_enable)
    app.router.add_post("/api/account/totp/disable", totp_disable)
    app.router.add_post("/api/account/passkeys/options", passkey_register_options)
    app.router.add_post("/api/account/passkeys/verify", passkey_register_verify)
    app.router.add_delete("/api/account/passkeys/{passkey_id}", delete_passkey)

    app.router.add_get("/api/admin/users", admin_users)
    app.router.add_post("/api/admin/users", admin_users)
    app.router.add_patch("/api/admin/users/{user_id}", admin_user)
    app.router.add_delete("/api/admin/users/{user_id}", admin_user)
    app.router.add_get("/api/admin/domains", admin_domains)
    app.router.add_post("/api/admin/domains", admin_domains)
    app.router.add_delete("/api/admin/domains/{domain_id}", delete_domain)

    app.router.add_get("/api/domains", domains)
    app.router.add_get("/api/history", history)
    app.router.add_delete("/api/history/{history_id}", delete_history)
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
