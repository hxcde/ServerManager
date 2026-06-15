import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

import pyotp
from aiohttp.test_utils import TestClient, TestServer


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import server  # noqa: E402


class ServerManagerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.database_path = tempfile.mktemp(suffix=".db")
        os.environ.update(
            {
                "APP_USERNAME": "admin",
                "APP_PASSWORD": "bootstrap-password-123",
                "DATABASE_PATH": self.database_path,
                "PUBLIC_URL": "",
                "TRUST_PROXY_HEADERS": "false",
            }
        )
        server.NOVNC_DIR = ROOT / "app" / "static"
        self.app = server.create_app()
        self.client = TestClient(TestServer(self.app))
        await self.client.start_server()
        self.origin = str(self.client.make_url("")).rstrip("/")

    async def asyncTearDown(self) -> None:
        await self.client.close()
        Path(self.database_path).unlink(missing_ok=True)

    async def login(
        self,
        totp: str = "",
        username: str = "admin",
        password: str = "bootstrap-password-123",
    ) -> None:
        response = await self.client.post(
            "/api/login/password",
            json={
                "username": username,
                "password": password,
                "totp": totp,
            },
            headers={"Origin": self.origin},
        )
        self.assertEqual(response.status, 200)

    async def csrf_token(self) -> str:
        response = await self.client.get("/")
        self.assertEqual(response.status, 200)
        html = await response.text()
        match = re.search(r'name="csrf-token" content="([^"]+)"', html)
        self.assertIsNotNone(match)
        return match.group(1)

    async def test_admin_user_domain_and_history_are_persistent(self) -> None:
        await self.login()
        csrf = await self.csrf_token()
        headers = {"Origin": self.origin, "X-CSRF-Token": csrf}

        response = await self.client.post(
            "/api/admin/users",
            json={
                "username": "operator",
                "displayName": "RDP Operator",
                "password": "operator-password-123",
                "isAdmin": False,
            },
            headers=headers,
        )
        self.assertEqual(response.status, 201)
        operator = await response.json()

        response = await self.client.post(
            "/api/admin/domains",
            json={"name": "CONTOSO"},
            headers=headers,
        )
        self.assertEqual(response.status, 201)

        self.app["db"].save_history(
            operator["id"],
            {
                "host": "server01",
                "port": 3389,
                "username": "administrator",
                "domain": "CONTOSO",
                "resolution": (1600, 900),
                "admin": True,
                "clipboard": True,
                "ignore_certificate": False,
            },
        )
        history = self.app["db"].list_history(operator["id"])
        self.assertEqual(history[0]["host"], "server01")
        self.assertNotIn("password", history[0])

        response = await self.client.post("/logout", json={}, headers=headers)
        self.assertEqual(response.status, 200)
        await self.login(
            username="operator",
            password="operator-password-123",
        )
        response = await self.client.get("/api/history")
        self.assertEqual(response.status, 200)
        user_history = await response.json()
        self.assertEqual(user_history[0]["host"], "server01")
        self.assertNotIn("password", user_history[0])

    async def test_totp_is_required_after_setup(self) -> None:
        await self.login()
        csrf = await self.csrf_token()
        headers = {"Origin": self.origin, "X-CSRF-Token": csrf}

        response = await self.client.post(
            "/api/account/totp/setup",
            json={},
            headers=headers,
        )
        self.assertEqual(response.status, 200)
        setup = await response.json()
        code = pyotp.TOTP(setup["secret"]).now()

        response = await self.client.post(
            "/api/account/totp/enable",
            json={"code": code},
            headers=headers,
        )
        self.assertEqual(response.status, 200)

        response = await self.client.post("/logout", json={}, headers=headers)
        self.assertEqual(response.status, 200)

        response = await self.client.post(
            "/api/login/password",
            json={"username": "admin", "password": "bootstrap-password-123"},
            headers={"Origin": self.origin},
        )
        self.assertEqual(response.status, 202)
        self.assertTrue((await response.json())["totpRequired"])

        await self.login(pyotp.TOTP(setup["secret"]).now())

    async def test_passkey_registration_options_are_generated(self) -> None:
        await self.login()
        csrf = await self.csrf_token()
        response = await self.client.post(
            "/api/account/passkeys/options",
            json={"name": "Testgerät"},
            headers={"Origin": self.origin, "X-CSRF-Token": csrf},
        )
        self.assertEqual(response.status, 200)
        payload = await response.json()
        self.assertIn("challenge", payload["publicKey"])
        self.assertEqual(payload["publicKey"]["rp"]["name"], "ServerManager")


if __name__ == "__main__":
    unittest.main()
