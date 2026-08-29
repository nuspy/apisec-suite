#!/usr/bin/env python3
"""Target di test deliberatamente vulnerabile.

Esiste per una ragione precisa: gli engine della suite inviano payload di
attacco, e provarli su sistemi di terzi non e' accettabile. Questo target gira
in locale, espone un OpenAPI auto-generato, e contiene difetti scelti perche'
*entrambi* gli engine trovino qualcosa:

    vulnapi   header di sicurezza assenti, CORS wildcard, cookie insicuri,
              JWT firmato con segreto debole, TRACE abilitato, /.env esposto
    APISCAN   BOLA su /users/{id}, BFLA su /admin/*, mass assignment su
              PATCH /users/{id}, SSRF su /fetch, rate limit assente

NON usare in produzione. NON esporre in rete: il bind di default e' 127.0.0.1.

    python tests/vulnerable_api.py            # http://127.0.0.1:8000
    python tests/vulnerable_api.py --port 9000
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
from typing import Any

from fastapi import FastAPI, Header, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

# Segreto volutamente debole: e' in ogni wordlist, vulnapi lo indovina.
JWT_SECRET = "secret"

app = FastAPI(
    title="Vulnerable Test API",
    version="1.0.0",
    description="Target di test locale per apisec-suite. Deliberatamente insicuro.",
)

# Dati fittizi. Nessun dato reale, nessuna PII vera.
USERS: dict[int, dict[str, Any]] = {
    1: {"id": 1, "username": "alice", "email": "alice@example.test",
        "role": "user", "ssn": "000-00-0001", "balance": 120.50},
    2: {"id": 2, "username": "bob", "email": "bob@example.test",
        "role": "user", "ssn": "000-00-0002", "balance": 980.00},
    3: {"id": 3, "username": "root", "email": "root@example.test",
        "role": "admin", "ssn": "000-00-0003", "balance": 0.0},
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_token(user_id: int, role: str = "user") -> str:
    """JWT HS256 con segreto debole, senza scadenza. Due difetti in tre righe."""
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": str(user_id), "role": role}).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(sig)}"


def _user_from_auth(authorization: str | None) -> dict[str, Any] | None:
    """Decodifica il JWT SENZA verificarne la firma. E' il punto, non una svista."""
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1]
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
        return USERS.get(int(claims.get("sub", 0)))
    except Exception:
        return None


@app.middleware("http")
async def insecure_headers(request: Request, call_next):
    """Header di risposta insicuri, applicati ovunque.

    Manca tutto quello che vulnapi cerca: HSTS, CSP, X-Frame-Options,
    X-Content-Type-Options. In piu' un CORS wildcard con credentials, che e'
    una combinazione che i browser rifiutano ma che gli scanner segnalano.
    """
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Server"] = "uvicorn/0.42.0 FastAPI/0.135.2"
    response.headers["X-Powered-By"] = "Python/3.10 FastAPI"
    return response


class LoginRequest(BaseModel):
    username: str
    password: str


class UserPatch(BaseModel):
    email: str | None = None
    # Mass assignment: role e balance non dovrebbero essere scrivibili dal client.
    role: str | None = None
    balance: float | None = None


@app.get("/health", summary="Health check")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/login", summary="Autenticazione")
def login(body: LoginRequest, response: Response) -> dict[str, str]:
    """Accetta qualunque password: e' un target di test, non un'autenticazione."""
    user = next((u for u in USERS.values() if u["username"] == body.username), None)
    if user is None:
        return JSONResponse({"detail": "unknown user"}, status_code=401)
    token = make_token(user["id"], user["role"])
    # Cookie senza Secure, senza HttpOnly, senza SameSite, senza Expires.
    response.set_cookie("session", token)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/users/{user_id}", summary="Dettaglio utente")
def get_user(user_id: int, authorization: str | None = Header(default=None)):
    """BOLA: chiede il token ma non controlla che user_id sia dell'utente."""
    if _user_from_auth(authorization) is None:
        return JSONResponse({"detail": "unauthorized"}, status_code=401)
    user = USERS.get(user_id)
    if user is None:
        return JSONResponse({"detail": "not found"}, status_code=404)
    return user  # include ssn e balance: excessive data exposure


@app.patch("/users/{user_id}", summary="Modifica utente")
def patch_user(user_id: int, body: UserPatch,
               authorization: str | None = Header(default=None)):
    """BOLA in scrittura + mass assignment su role."""
    if _user_from_auth(authorization) is None:
        return JSONResponse({"detail": "unauthorized"}, status_code=401)
    user = USERS.get(user_id)
    if user is None:
        return JSONResponse({"detail": "not found"}, status_code=404)
    for field, value in body.model_dump(exclude_none=True).items():
        user[field] = value  # nessuna allowlist dei campi scrivibili
    return user


@app.get("/admin/users", summary="Elenco completo utenti (admin)")
def admin_users(authorization: str | None = Header(default=None)):
    """BFLA: dice 'admin' nel path ma non verifica il ruolo."""
    if _user_from_auth(authorization) is None:
        return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return {"users": list(USERS.values())}


@app.delete("/admin/users/{user_id}", summary="Cancella utente (admin)")
def admin_delete(user_id: int, authorization: str | None = Header(default=None)):
    if _user_from_auth(authorization) is None:
        return JSONResponse({"detail": "unauthorized"}, status_code=401)
    USERS.pop(user_id, None)
    return {"deleted": user_id}


@app.get("/fetch", summary="Recupera una URL remota")
def fetch(url: str):
    """SSRF: non valida lo schema ne' la destinazione.

    Non esegue davvero la richiesta - il target di test non deve diventare uno
    strumento di attacco. Rispecchia la URL, che basta agli scanner per
    riconoscere il pattern.
    """
    return {"requested": url, "note": "fetch simulato, nessuna richiesta reale"}


@app.get("/search", summary="Ricerca utenti")
def search(q: str = ""):
    """Riflette l'input non sanificato: pattern di XSS/injection."""
    matches = [u for u in USERS.values() if q.lower() in u["username"].lower()]
    return {"query": q, "count": len(matches), "results": matches}


@app.get("/.env", include_in_schema=False)
def leaked_env() -> PlainTextResponse:
    """File di configurazione esposto. Valori fittizi, ma il pattern e' reale."""
    return PlainTextResponse(
        "APP_ENV=production\n"
        "DATABASE_URL=postgres://fake:fake@localhost:5432/fake\n"
        "JWT_SECRET=secret\n"
    )


@app.get("/api/v1/debug", include_in_schema=False)
def debug_info() -> dict[str, Any]:
    """Endpoint non documentato nell'OpenAPI: improper inventory management."""
    return {"users_loaded": len(USERS), "jwt_secret_len": len(JWT_SECRET),
            "framework": "FastAPI", "debug": True}


@app.api_route("/trace-me", methods=["TRACE"], include_in_schema=False)
def trace_endpoint(request: Request) -> PlainTextResponse:
    """TRACE abilitato: vulnapi lo cerca esplicitamente."""
    return PlainTextResponse(f"TRACE {request.url.path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (default 127.0.0.1, NON usare 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    # vulnapi rifiuta un OpenAPI senza `servers` ("no valid base url has been
    # found"). FastAPI non lo genera da solo, quindi lo si mette qui.
    app.servers = [{"url": f"http://{args.host}:{args.port}"}]

    import uvicorn
    print(f"[*] Target di test vulnerabile su http://{args.host}:{args.port}")
    print(f"[*] OpenAPI: http://{args.host}:{args.port}/openapi.json")
    print("[!] Deliberatamente insicuro. Solo per test locali.")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
