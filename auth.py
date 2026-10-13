"""Autenticación contra LaLiga Fantasy (Azure B2C, Authorization Code + PKCE).

Flujo:
  * Primera vez: abre un navegador para iniciar sesión y captura automáticamente
    la redirección authredirect://; no hace falta copiar/pegar la URL.
  * Después: intenta reutilizar el token guardado o renovarlo con refresh_token.

Los tokens se guardan fuera del repo (por defecto en ~/.laliga-clausulas/tokens.json,
configurable con LALIGA_TOKENS_FILE). Nunca se imprimen.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import requests

CLIENT_ID = "af88bcff-1157-40a0-b579-030728aacf0b"
B2C_BASE = "https://login.laliga.es/laligadspprob2c.onmicrosoft.com/oauth2/v2.0"
POLICY = "B2C_1A_5ULAIP_PARAMETRIZED_SIGNIN"
REDIRECT_URI = "authredirect://com.lfp.laligafantasy"
SCOPE = "openid offline_access"

EXPIRY_MARGIN_S = 300
HTTP_TIMEOUT = 20
LOGIN_TIMEOUT_S = 300


class AuthError(Exception):
    """Fallo de autenticación (los mensajes nunca incluyen tokens)."""


# --------------------------------------------------------------------------- #
# Almacenamiento de tokens
# --------------------------------------------------------------------------- #
def token_path() -> Path:
    override = os.environ.get("LALIGA_TOKENS_FILE")
    if override:
        return Path(override)
    return Path.home() / ".laliga-clausulas" / "tokens.json"


def load_tokens(path: Path | None = None) -> dict | None:
    path = path or token_path()
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as exc:
        raise AuthError(f"El fichero de tokens está corrupto: {path}") from exc


def save_tokens(tokens: dict, path: Path | None = None) -> Path:
    path = path or token_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    try:
        os.chmod(tmp, 0o600)  # En Windows apenas tiene efecto.
    except OSError:
        pass
    os.replace(tmp, path)
    return path


# --------------------------------------------------------------------------- #
# PKCE y URL de autorización
# --------------------------------------------------------------------------- #
def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_pkce() -> tuple[str, str]:
    """Devuelve (verifier, challenge S256)."""
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def build_authorize_url(challenge: str, state: str) -> str:
    params = {
        "p": POLICY,
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "nonce": state,
    }
    return f"{B2C_BASE}/authorize?{urlencode(params)}"


def extract_code(redirect_url: str, expected_state: str | None = None) -> str:
    """Extrae y valida el código de la URL de redirección."""
    redirect_url = redirect_url.strip()
    if not redirect_url:
        raise AuthError("La URL de redirección está vacía.")

    parsed = urlparse(redirect_url)
    query = parse_qs(parsed.query)
    code = (query.get("code") or [None])[0]
    if not code:
        raise AuthError("No se encontró el parámetro code en la redirección.")

    returned_state = (query.get("state") or [None])[0]
    if expected_state and returned_state != expected_state:
        raise AuthError(
            "El state de la redirección no coincide con el intento de login actual."
        )
    return code


# --------------------------------------------------------------------------- #
# Llamadas al endpoint de tokens
# --------------------------------------------------------------------------- #
def _post_token(data: dict) -> dict:
    try:
        response = requests.post(
            f"{B2C_BASE}/token?p={POLICY}",
            data=data,
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise AuthError(f"No se pudo contactar con el servidor de login: {exc}") from exc

    try:
        body = response.json()
    except ValueError:
        raise AuthError(
            f"Respuesta no JSON del login (HTTP {response.status_code})."
        ) from None

    if not response.ok:
        error = body.get("error", "error_desconocido")
        description = body.get("error_description", "sin detalles")
        raise AuthError(f"HTTP {response.status_code}: {error} - {description}")
    return body


def _normalize(body: dict, previous: dict | None = None) -> dict:
    """Añade metadatos y conserva el refresh_token anterior si no llega uno nuevo."""
    now = int(time.time())
    tokens = dict(body)
    if previous and not tokens.get("refresh_token"):
        tokens["refresh_token"] = previous.get("refresh_token")
    ttl = int(tokens.get("id_token_expires_in") or tokens.get("expires_in") or 3600)
    tokens["client_id"] = CLIENT_ID
    tokens["obtained_at"] = now
    tokens["expires_at"] = now + ttl
    return tokens


def exchange_code(code: str, verifier: str) -> dict:
    body = _post_token(
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
            "scope": SCOPE,
        }
    )
    return _normalize(body)


def refresh(tokens: dict) -> dict:
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        raise AuthError("No hay refresh_token guardado.")

    body = _post_token(
        {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": refresh_token,
            "scope": SCOPE,
        }
    )
    return _normalize(body, previous=tokens)


# --------------------------------------------------------------------------- #
# Inicio de sesión automático en navegador
# --------------------------------------------------------------------------- #
def browser_profile_dir() -> Path:
    """Perfil persistente separado para conservar cookies de LaLiga."""
    return token_path().parent / "browser-profile"


def capture_redirect_with_browser(
    url: str,
    expected_state: str,
    timeout_s: int = LOGIN_TIMEOUT_S,
    profile_dir: Path | None = None,
    headless: bool = False,
) -> str:
    """Abre un navegador, permite iniciar sesión y captura authredirect:// automáticamente."""
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise AuthError(
            "Falta Playwright. Instálalo con: pip install playwright"
        ) from exc

    profile_dir = profile_dir or browser_profile_dir()
    profile_dir.mkdir(parents=True, exist_ok=True)
    captured: list[str] = []

    def capture(candidate: str | None) -> None:
        if not candidate or not candidate.startswith("authredirect:"):
            return
        parsed = urlparse(candidate)
        query = parse_qs(parsed.query)
        code = (query.get("code") or [None])[0]
        state = (query.get("state") or [None])[0]
        if code and state == expected_state and candidate not in captured:
            captured.append(candidate)

    with sync_playwright() as playwright:
        context = None
        launch_errors = []

        # Primero prueba Chrome instalado; si no está disponible, Chromium de Playwright.
        for options in ({"channel": "chrome"}, {}):
            try:
                context = playwright.chromium.launch_persistent_context(
                    str(profile_dir),
                    headless=headless,
                    **options,
                )
                break
            except PlaywrightError as exc:
                launch_errors.append(str(exc))

        if context is None:
            raise AuthError(
                "No se pudo iniciar Chrome ni Chromium. Ejecuta "
                "'playwright install chromium' y vuelve a intentarlo."
            )

        try:
            # En algunos sistemas el esquema personalizado se ve como request
            # fallida; en otros aparece como navegación del frame.
            context.on("request", lambda request: capture(request.url))
            context.on("requestfailed", lambda request: capture(request.url))

            page = context.pages[0] if context.pages else context.new_page()
            page.on("framenavigated", lambda frame: capture(frame.url))

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=60000)
            except PlaywrightError:
                # La navegación a authredirect:// puede ser rechazada por Chromium
                # después de que el evento de redirección ya se haya emitido.
                capture(page.url)

            deadline = time.monotonic() + timeout_s
            while not captured and time.monotonic() < deadline:
                try:
                    capture(page.url)
                    page.wait_for_timeout(200)
                except PlaywrightError:
                    # El navegador puede cambiar de página al recibir la redirección.
                    capture(page.url)
                    if not captured:
                        time.sleep(0.2)

            if not captured:
                raise AuthError(
                    f"No se detectó la redirección de login en {timeout_s} segundos. "
                    "Comprueba que has completado el inicio de sesión en el navegador."
                )

            return captured[-1]
        finally:
            try:
                context.close()
            except Exception:
                pass


def interactive_login() -> dict:
    """Login en navegador; no solicita copiar ni pegar ninguna URL."""
    verifier, challenge = make_pkce()
    state = secrets.token_urlsafe(16)
    authorize_url = build_authorize_url(challenge, state)

    print("Abriendo el navegador de LaLiga Fantasy...")
    print("Inicia sesión en la ventana que se abre; espera aquí al terminar.")

    redirect_url = capture_redirect_with_browser(
        authorize_url,
        expected_state=state,
        timeout_s=LOGIN_TIMEOUT_S,
    )
    code = extract_code(redirect_url, expected_state=state)
    return exchange_code(code, verifier)


# --------------------------------------------------------------------------- #
# API pública del módulo
# --------------------------------------------------------------------------- #
def is_fresh(tokens: dict | None, now: float | None = None) -> bool:
    if not tokens or not (tokens.get("id_token") or tokens.get("access_token")):
        return False
    now = time.time() if now is None else now
    return tokens.get("expires_at", 0) - now > EXPIRY_MARGIN_S


def get_id_token(
    path: Path | None = None,
    interactive: bool = True,
    force_refresh: bool = False,
) -> str:
    """Devuelve un token válido: caché -> refresh -> login automático."""
    path = path or token_path()
    tokens = load_tokens(path)

    if not force_refresh and is_fresh(tokens):
        return tokens.get("id_token") or tokens["access_token"]

    if tokens and tokens.get("refresh_token"):
        try:
            tokens = refresh(tokens)
            save_tokens(tokens, path)
            token = tokens.get("id_token") or tokens.get("access_token")
            if token:
                return token
            raise AuthError("La respuesta de renovación no contenía un token.")
        except AuthError as exc:
            if not interactive:
                raise AuthError(
                    f"No se pudo renovar la sesión ({exc}). Ejecuta el login."
                ) from exc

    if not interactive:
        raise AuthError("No hay sesión válida. Ejecuta el login.")

    tokens = interactive_login()
    save_tokens(tokens, path)
    token = tokens.get("id_token") or tokens.get("access_token")
    if not token:
        raise AuthError("La respuesta del login no contenía un token.")
    return token


if __name__ == "__main__":
    API_BASE = "https://fantasy-api.llt-services.com/api"
    tokens_before = load_tokens()
    print("Fichero de tokens:", token_path())
    print("Sesión guardada antes:", "sí" if tokens_before else "no")

    try:
        token = get_id_token()
    except AuthError as exc:
        raise SystemExit(f"Error de autenticación: {exc}") from exc

    saved_tokens = load_tokens() or {}
    print("Token obtenido correctamente.")
    print("Caduca en (s):", int(saved_tokens.get("expires_at", 0) - time.time()))
    print("Tiene refresh_token:", bool(saved_tokens.get("refresh_token")))
    if saved_tokens.get("refresh_token_expires_in"):
        print(
            "Validez del refresh_token (días):",
            int(saved_tokens["refresh_token_expires_in"]) // 86400,
        )

    try:
        response = requests.get(
            f"{API_BASE}/v4/user/me",
            params={"x-lang": "es"},
            headers={"Authorization": f"Bearer {token}", "x-lang": "es"},
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise SystemExit(f"No se pudo consultar el perfil de LaLiga: {exc}") from exc

    print("GET /v4/user/me ->", response.status_code)
    if response.ok:
        print("Usuario:", response.json().get("managerName"))
