"""Cliente inicial para la API de LaLiga Fantasy.

Usa la autenticación definida en auth.py.
No imprime ni guarda tokens en este módulo.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import requests

from auth import AuthError, HTTP_TIMEOUT, get_id_token


API_BASE = "https://fantasy-api.llt-services.com/api"


class APIError(Exception):
    """Error al consultar la API de LaLiga Fantasy."""


class LaLigaAPI:
    """Cliente HTTP autenticado para LaLiga Fantasy."""

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "x-lang": "es",
            }
        )

    def _authenticate(self) -> None:
        """Obtiene un token válido y lo añade a la sesión HTTP."""
        try:
            token = get_id_token()
        except AuthError as exc:
            raise APIError(f"No se pudo autenticar con LaLiga: {exc}") from exc

        self.session.headers["Authorization"] = f"Bearer {token}"

    def get_json(self, endpoint: str) -> Any:
        """Realiza una petición GET y devuelve la respuesta JSON."""
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint

        self._authenticate()
        url = f"{API_BASE}{endpoint}"

        try:
            response = self.session.get(url, timeout=HTTP_TIMEOUT)
        except requests.RequestException as exc:
            raise APIError(
                f"No se pudo conectar con la API ({type(exc).__name__})."
            ) from exc

        if response.status_code == 401:
            # Fuerza una renovación o un nuevo login y reintenta una vez.
            try:
                token = get_id_token(force_refresh=True)
            except AuthError as exc:
                raise APIError(
                    "La API rechazó la sesión y no se pudo renovar."
                ) from exc

            self.session.headers["Authorization"] = f"Bearer {token}"

            try:
                response = self.session.get(url, timeout=HTTP_TIMEOUT)
            except requests.RequestException as exc:
                raise APIError(
                    f"Falló la segunda petición ({type(exc).__name__})."
                ) from exc

        if not response.ok:
            raise APIError(
                f"API HTTP {response.status_code} al consultar {endpoint}."
            )

        try:
            return response.json()
        except ValueError as exc:
            raise APIError(
                f"La API no devolvió JSON válido para {endpoint}."
            ) from exc

    def get_my_profile(self) -> dict[str, Any]:
        """Consulta el perfil del usuario autenticado."""
        data = self.get_json("/v4/user/me")

        if not isinstance(data, dict):
            raise APIError("El perfil no tiene el formato JSON esperado.")

        return data


def describe_structure(value: Any, depth: int = 0, max_depth: int = 2) -> Any:
    """Describe las claves y tipos de un JSON sin mostrar sus valores."""
    if depth >= max_depth:
        if isinstance(value, dict):
            return f"objeto con {len(value)} campos"
        if isinstance(value, list):
            return f"lista con {len(value)} elementos"
        return type(value).__name__

    if isinstance(value, dict):
        return {
            key: describe_structure(item, depth + 1, max_depth)
            for key, item in value.items()
        }

    if isinstance(value, list):
        if not value:
            return "lista vacía"

        return {
            "tipo": "lista",
            "cantidad": len(value),
            "primer_elemento": describe_structure(
                value[0], depth + 1, max_depth
            ),
        }

    return type(value).__name__


def main() -> int:
    api = LaLigaAPI()

    try:
        profile = api.get_my_profile()
    except APIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print("Conexión con LaLiga Fantasy correcta.")
    print("Campos de la respuesta del perfil:")
    print(json.dumps(
        describe_structure(profile),
        ensure_ascii=False,
        indent=2,
    ))

    if "managerName" in profile:
        print("El perfil contiene el campo managerName.")

    print()
    print(
        "Siguiente paso: identificar los endpoints de jugadores "
        "y los campos relacionados con las cláusulas."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())