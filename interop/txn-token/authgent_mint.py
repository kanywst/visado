"""Mint Txn-Tokens with authgent-server and print them in the harness input format.

Runs the real FastAPI app in-process with an in-memory SQLite database, the
way authgent's own server/tests/conftest.py does, and requests Txn-Tokens
through RFC 8693 token exchange at POST /token. The JWKS comes from
GET /.well-known/jwks.json. authgent stamps iat with the wall clock, so each
case carries its own `now` derived from the token.

Usage: python -I authgent_mint.py > authgent-minted.json
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
import sys

# authgent's structlog writes to stdout; keep stdout for the JSON result.
RESULT = sys.stdout
sys.stdout = sys.stderr

os.environ["AUTHGENT_SECRET_KEY"] = "interop-only-secret-key-64-characters-long-padding-padding-pad!!"
os.environ["AUTHGENT_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["AUTHGENT_CONSENT_MODE"] = "auto_approve"
os.environ["AUTHGENT_REGISTRATION_POLICY"] = "open"
os.environ["AUTHGENT_SERVER_URL"] = "http://localhost:8000"

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from authgent_server.app import create_app  # noqa: E402
from authgent_server.config import reset_settings  # noqa: E402
from authgent_server.dependencies import get_db_session, reset_providers  # noqa: E402
from authgent_server.models.base import Base  # noqa: E402

TRUST_DOMAIN = "trust-domain.example"
ISSUER = "http://localhost:8000"
TXN = "urn:ietf:params:oauth:token-type:txn_token"
EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TCTX = {
    "action": "BUY",
    "ticker": "MSFT",
    "quantity": "100",
    "customer_type": {"geo": "US", "level": "VIP"},
}
RCTX = {"channel": "mobile"}


def b64d(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def payload(token: str) -> dict:
    return json.loads(b64d(token.split(".")[1]))


def tamper(token: str) -> str:
    head, body, sig = token.split(".")
    raw = bytearray(b64d(sig))
    raw[0] ^= 0x01
    return f"{head}.{body}." + base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()


async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return async_sessionmaker(engine, expire_on_commit=False)()


def client() -> TestClient:
    reset_settings()
    reset_providers()
    app = create_app()
    db = asyncio.run(session())

    async def override():
        yield db

    app.dependency_overrides[get_db_session] = override
    return TestClient(app)


def register(c: TestClient, grant_types: list[str]) -> dict:
    r = c.post(
        "/register",
        json={
            "client_name": f"interop-{secrets.token_hex(4)}",
            "grant_types": grant_types,
            "scope": "trade.stocks read write",
        },
    )
    r.raise_for_status()
    return r.json()


def access_token(c: TestClient, creds: dict, scope: str | None) -> str:
    data = {
        "grant_type": "client_credentials",
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
    }
    if scope is not None:
        data["scope"] = scope
    r = c.post("/token", data=data)
    r.raise_for_status()
    return r.json()["access_token"]


def txn_token(c: TestClient, caller: dict, subject: str, scope: str | None, ctx: bool) -> dict:
    data = {
        "grant_type": EXCHANGE,
        "client_id": caller["client_id"],
        "client_secret": caller["client_secret"],
        "subject_token": subject,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "requested_token_type": TXN,
        "audience": TRUST_DOMAIN,
    }
    if scope is not None:
        data["scope"] = scope
    if ctx:
        data["request_details"] = json.dumps(TCTX)
        data["request_context"] = json.dumps(RCTX)
    r = c.post("/token", data=data)
    return {"status": r.status_code, "body": r.json()}


def main() -> int:
    c = client()
    parent = register(c, ["client_credentials"])
    caller = register(c, ["client_credentials", EXCHANGE])
    scoped = access_token(c, parent, "trade.stocks")

    full = txn_token(c, caller, scoped, "trade.stocks", ctx=True)
    bare = txn_token(c, caller, scoped, "trade.stocks", ctx=False)
    # A whitespace-only scope passes authgent's subset check (" ".split() is
    # empty) and is copied into the token as is.
    blank = txn_token(c, caller, scoped, " ", ctx=False)
    for name, resp in (("full", full), ("bare", bare), ("blank-scope", blank)):
        if resp["status"] != 200:
            print(f"authgent_mint: {name}: HTTP {resp['status']}: {resp['body']}", file=sys.stderr)
            return 1
    token = full["body"]["access_token"]
    claims = payload(token)
    at, exp = claims["iat"], claims["exp"]

    cases = [
        {"id": "authgent-valid", "token": token, "now": at + 1, "expect": "accept",
         "why": "§9.2 all REQUIRED claims, tctx and rctx"},
        {"id": "authgent-no-ctx", "token": bare["body"]["access_token"], "now": at + 1, "expect": "accept",
         "why": "no request_details: rctx only (authgent always adds rctx)"},
        {"id": "authgent-expired", "token": token, "now": exp + 60, "expect": "reject",
         "why": "§12.2 not expired; verified 60 s after exp"},
        {"id": "authgent-exp-equals-now", "token": token, "now": exp, "expect": "reject",
         "why": "RFC 7519 §4.1.4: now must be before exp (leeway allowed)"},
        {"id": "authgent-wrong-aud", "token": token, "now": at + 1, "trust_domain": "other-domain.example",
         "expect": "reject", "why": "§9.2 aud, §12.2 trust domain; verifier in another trust domain"},
        {"id": "authgent-tampered", "token": tamper(token), "now": at + 1, "expect": "reject",
         "why": "§12.2 signature"},
        {"id": "authgent-blank-scope", "token": blank["body"]["access_token"], "now": at + 1,
         "expect": "unspecified",
         "why": "scope=\" \" requested: authgent issues scope \" \"; §9.2 scope REQUIRED, emptiness not addressed"},
    ]
    jwks = c.get("/.well-known/jwks.json").json()
    out = {
        "minter": "authgent",
        "trust_domain": TRUST_DOMAIN,
        "issuer": ISSUER,
        "now": at + 1,
        "keys": jwks["keys"],
        "header": json.loads(b64d(token.split(".")[0])),
        "claim_names": sorted(claims),
        "cases": cases,
    }
    json.dump(out, RESULT, indent=2, sort_keys=True)
    RESULT.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
