# /// script
# requires-python = ">=3.11"
# dependencies = ["PyJWT[crypto]>=2.10,<3", "requests>=2.32,<3"]
# ///
"""Run with uv run tests/oidc/browser_flow.py target/debug/openobserve."""

import base64
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import rsa


class Issuer(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Authorization codes must stay out of HTTP logs.

    def json(self, payload, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_GET(self):
        server = self.server
        path = urlsplit(self.path)
        if path.path.endswith("/.well-known/openid-configuration"):
            self.json(
                {
                    "issuer": server.issuer,
                    "authorization_endpoint": server.issuer + "/authorize",
                    "token_endpoint": server.issuer + "/token",
                    "jwks_uri": server.issuer + "/keys",
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                }
            )
        elif path.path == "/keys":
            jwk = jwt.algorithms.RSAAlgorithm.to_jwk(
                server.key.public_key(), as_dict=True
            )
            self.json({"keys": [dict(jwk, kid="fixture", alg="RS256", use="sig")]})
        elif path.path == "/authorize":
            q = {k: v[0] for k, v in parse_qs(path.query).items()}
            assert q["client_id"] == "test-client" and q["response_type"] == "code"
            assert (
                q["redirect_uri"] == server.callback
                and q["code_challenge_method"] == "S256"
            )
            assert "openid" in q["scope"].split() and q["nonce"] and q["state"]
            code = secrets.token_urlsafe()
            server.codes[code] = q
            self.send_response(302)
            self.send_header(
                "Location",
                server.callback + "?" + urlencode({"code": code, "state": q["state"]}),
            )
            self.end_headers()
        else:
            self.send_error(404)

    def do_POST(self):
        server = self.server
        q = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        request = server.codes.pop(q["code"][0], None)
        if not request or self.path != "/token":
            return self.json({"error": "invalid_grant"}, 400)
        assert q["redirect_uri"] == [server.callback] and q["grant_type"] == [
            "authorization_code"
        ]
        auth = "Basic " + base64.b64encode(b"test-client:test-secret").decode()
        assert self.headers["Authorization"] == auth
        digest = hashlib.sha256(q["code_verifier"][0].encode()).digest()
        assert (
            base64.urlsafe_b64encode(digest).decode().rstrip("=")
            == request["code_challenge"]
        )
        now = int(time.time())
        claims = {
            "iss": server.issuer,
            "sub": server.subject,
            "aud": "test-client",
            "nonce": request["nonce"],
            "iat": now,
            "exp": now + 300,
            "email": server.email,
            "email_verified": True,
        }
        token = jwt.encode(
            claims, server.key, algorithm="RS256", headers={"kid": "fixture"}
        )
        self.json(
            {
                "access_token": secrets.token_urlsafe(),
                "token_type": "Bearer",
                "id_token": token,
            }
        )


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def app(binary, directory, port, settings):
    base = f"http://127.0.0.1:{port}"
    env = {k: v for k, v in os.environ.items() if not k.startswith("ZO_")}
    env.update(
        ZO_LOCAL_MODE="true",
        ZO_LOCAL_MODE_STORAGE="disk",
        ZO_TELEMETRY="false",
        ZO_HTTP_ADDR="127.0.0.1",
        ZO_GRPC_ADDR="127.0.0.1",
        ZO_HTTP_PORT=str(port),
        ZO_GRPC_PORT=str(free_port()),
        ZO_DATA_DIR=str(Path(directory) / "data") + "/",
        ZO_ROOT_USER_EMAIL=ROOT,
        ZO_ROOT_USER_PASSWORD=PASSWORD,
        ZO_WEB_URL=base,
        **settings,
    )
    with open(Path(directory) / "server.log", "ab") as log:
        process = subprocess.Popen(
            [binary], cwd=directory, env=env, stdout=log, stderr=log
        )
        try:
            for _ in range(300):
                if process.poll() is not None:
                    raise RuntimeError(
                        f"OpenObserve exited during startup ({process.returncode})"
                    )
                try:
                    if requests.get(base + "/healthz", timeout=1).ok:
                        break
                except requests.ConnectionError:
                    pass
                time.sleep(0.2)
            else:
                raise RuntimeError("OpenObserve startup timed out")
            yield base
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def flow(browser, base, success):
    login = browser.get(base + "/auth/oidc/login", allow_redirects=False, timeout=20)
    assert login.is_redirect, login.status_code
    consent = requests.get(login.headers["Location"], allow_redirects=False, timeout=5)
    assert consent.is_redirect
    response = browser.get(
        consent.headers["Location"], allow_redirects=False, timeout=20
    )
    assert response.is_redirect
    assert response.headers["Location"].endswith(
        "/web/cb?oidc=1" if success else "/web/login?oidc_error=1"
    )
    return consent.headers["Location"]


ROOT = "root@example.test"
HUMAN = "member@example.test"
PASSWORD = "T3st!" + secrets.token_urlsafe(24)


def test_flow(binary, directory, issuer):
    port = free_port()
    with app(binary, directory, port, {}) as base:
        assert requests.get(base + "/auth/oidc/login", timeout=5).status_code == 404
        native = requests.post(
            base + "/auth/login", json={"name": ROOT, "password": PASSWORD}, timeout=5
        )
        assert native.ok and native.json()["status"]
        user = requests.post(
            base + "/api/default/users",
            auth=(ROOT, PASSWORD),
            json={"email": HUMAN, "password": PASSWORD, "role": "admin"},
            timeout=5,
        )
        assert user.ok, user.status_code
        machine = requests.post(
            base + "/api/default/service_accounts",
            auth=(ROOT, PASSWORD),
            json={"email": "machine@example.test"},
            timeout=5,
        )
        assert machine.ok, machine.status_code
        machine_creds = machine.json()
        passcode = requests.get(
            base + "/api/default/passcode", auth=(ROOT, PASSWORD), timeout=5
        ).json()["data"]

    issuer.callback = base + "/auth/oidc/callback"
    settings = {
        "ZO_OIDC_ENABLED": "true",
        "ZO_OIDC_ISSUER": issuer.issuer,
        "ZO_OIDC_CLIENT_ID": "test-client",
        "ZO_OIDC_CLIENT_SECRET": "test-secret",
        "ZO_OIDC_REDIRECT_URI": issuer.callback,
        "ZO_OIDC_ALLOW_INSECURE_HTTP": "true",
        "ZO_OIDC_COOKIE_SECURE": "false",
        "ZO_OIDC_ONLY": "true",
        "ZO_OIDC_ACCOUNT_LINKS": json.dumps(
            [{"issuer": issuer.issuer, "subject": "approved", "email": HUMAN}]
        ),
    }
    with app(binary, directory, port, settings):
        issuer.subject, issuer.email = "unapproved", HUMAN
        with requests.Session() as browser:
            flow(browser, base, False)
            assert (
                browser.get(base + "/auth/oidc/session", timeout=5).status_code == 401
            )
            issuer.subject = "approved"
            callback = flow(browser, base, True)
            profile = browser.get(base + "/auth/oidc/session", timeout=5).json()
            assert profile["email"] == HUMAN and profile["exp"] > time.time()
            assert browser.get(base + "/api/default/config", timeout=5).ok
            replay = browser.get(callback, allow_redirects=False, timeout=5)
            assert replay.headers["Location"].endswith("oidc_error=1")
            old = browser.cookies.copy()
            flow(browser, base, True)
            assert (
                requests.get(
                    base + "/auth/oidc/session", cookies=old, timeout=5
                ).status_code
                == 401
            )
            previous = browser.cookies.copy()
            assert (
                browser.post(
                    base + "/auth/oidc/logout",
                    headers={"Origin": issuer.issuer},
                    timeout=5,
                ).status_code
                == 403
            )
            assert (
                browser.post(
                    base + "/auth/oidc/logout", headers={"Origin": base}, timeout=5
                ).status_code
                == 204
            )
            assert (
                requests.get(
                    base + "/auth/oidc/session", cookies=previous, timeout=5
                ).status_code
                == 401
            )
        for email in [ROOT, HUMAN]:
            assert requests.post(
                base + "/auth/login",
                json={"name": email, "password": PASSWORD},
                timeout=5,
            ).status_code in (401, 403)
            assert requests.get(
                base + "/api/default/config", auth=(email, PASSWORD), timeout=5
            ).status_code in (401, 403)
        ingest = requests.post(
            base + "/api/default/oidc_smoke/_json",
            json=[{"message": "ok"}],
            auth=(passcode["user"], passcode["passcode"]),
            timeout=10,
        )
        assert ingest.ok, ingest.status_code
        otlp = requests.post(
            base + "/api/default/v1/logs",
            auth=(passcode["user"], passcode["passcode"]),
            json={
                "resourceLogs": [
                    {"scopeLogs": [{"logRecords": [{"body": {"stringValue": "ok"}}]}]}
                ]
            },
            timeout=10,
        )
        assert otlp.ok, otlp.status_code
        machine = requests.get(
            base + "/api/default/config",
            auth=(machine_creds["user"], machine_creds["token"]),
            timeout=5,
        )
        assert machine.ok, machine.status_code

    settings.update(
        ZO_OIDC_ACCOUNT_LINKS="[]",
        ZO_OIDC_PROVISIONING_ENABLED="true",
        ZO_OIDC_EMERGENCY_USER=ROOT,
        ZO_OIDC_SESSION_MAX_AGE="2",
    )
    with app(binary, directory, port, settings):
        assert requests.get(
            base + "/api/default/config", auth=(ROOT, PASSWORD), timeout=5
        ).ok
        with requests.Session() as browser:
            flow(browser, base, False)  # An explicitly linked account lost approval.
            issuer.subject = "different-subject"
            flow(
                browser, base, False
            )  # Verified email collision with an existing user.
            issuer.email = "new@example.test"
            issuer.subject = "new-subject"
            flow(browser, base, True)
            assert not browser.get(base + "/api/default/config", timeout=5).ok
            expiry = browser.get(base + "/auth/oidc/session", timeout=5).json()["exp"]
            time.sleep(max(0, expiry - time.time()) + 0.2)
            assert (
                browser.get(base + "/auth/oidc/session", timeout=5).status_code == 401
            )


if __name__ == "__main__":
    binary = Path(sys.argv[1]).resolve(strict=True)
    with (
        TemporaryDirectory() as directory,
        ThreadingHTTPServer(("127.0.0.1", 0), Issuer) as issuer,
    ):
        issuer.issuer = f"http://127.0.0.1:{issuer.server_port}"
        issuer.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer.codes = {}
        Thread(target=issuer.serve_forever, daemon=True).start()
        try:
            test_flow(binary, directory, issuer)
        finally:
            issuer.shutdown()
    print("OIDC browser flow and SQLite policy checks passed")
