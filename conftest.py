import json

import pytest
from werkzeug.security import generate_password_hash

import server

TEST_USER = "tester"
TEST_PASSWORD = "s3cret"

# Минимальный валидный PAC-шаблон с маркерами, вокруг которых работает парсер.
PAC_TEMPLATE = (
    "function FindProxyForURL(url, host)\n"
    "{\n"
    '    $Proxy = "PROXY proxy:8090";\n\n'
    "    //PROXY\n\n"
    "    //DIRECT\n\n"
    "    //constants\n"
    '    if (shExpMatch(url, "localhost")) {return "DIRECT";}\n'
    "}\n"
)


@pytest.fixture
def isolated_files(tmp_path, monkeypatch):
    cfg = tmp_path / "config.json"
    users = tmp_path / "users.json"
    pac = tmp_path / "wpad.dat"

    pac.write_text(PAC_TEMPLATE, encoding="utf-8")
    cfg.write_text(
        json.dumps({
            "routing_file": str(pac),
            "proxies": [{"name": "first", "address": "192.0.2.11:3128"}],
        }),
        encoding="utf-8",
    )
    users.write_text(
        json.dumps({TEST_USER: generate_password_hash(TEST_PASSWORD)}),
        encoding="utf-8",
    )

    monkeypatch.setattr(server, "CONFIG_FILE", str(cfg))
    monkeypatch.setattr(server, "USERS_FILE", str(users))

    return {"config": cfg, "users": users, "pac": pac}


@pytest.fixture(autouse=True)
def _clear_ban_state():
    """fail2ban без Redis держит счётчики в общем модульном словаре — чистим его
    до и после каждого теста, чтобы баны не протекали между тестами."""
    server._ban_mem.clear()
    yield
    server._ban_mem.clear()


@pytest.fixture
def client(isolated_files):
    server.app.config.update(TESTING=True)
    server.app.config["SESSION_COOKIE_SECURE"] = False
    return server.app.test_client()


@pytest.fixture
def auth_client(client):
    resp = client.post(
        "/api/login",
        json={"username": TEST_USER, "password": TEST_PASSWORD},
    )
    assert resp.status_code == 200, "фикстура auth_client: логин не удался"
    return client
