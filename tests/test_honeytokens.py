import json

import server
from conftest import TEST_USER, TEST_PASSWORD


def _set_honeytokens(isolated_files, tokens):
    """Дописывает список логинов-приманок в изолированный config.json."""
    cfg = isolated_files["config"]
    data = json.loads(cfg.read_text(encoding="utf-8"))
    data["honeytokens"] = tokens
    cfg.write_text(json.dumps(data), encoding="utf-8")


def test_honeytoken_bans_immediately(client, isolated_files):
    """Одной попытки под логином-приманкой хватает, чтобы забанить IP."""
    _set_honeytokens(isolated_files, ["admin"])
    ip = "203.0.113.70"
    resp = client.post(
        "/api/login",
        json={"username": "admin", "password": "whatever"},
        environ_overrides={"REMOTE_ADDR": ip},
    )
    # Обезличенный 401 — атакующий не отличит приманку от обычной ошибки.
    assert resp.status_code == 401
    # А IP уже забанен — следующий запрос ловит 429 ещё до формы входа.
    after = client.get("/", environ_overrides={"REMOTE_ADDR": ip})
    assert after.status_code == 429


def test_honeytoken_match_is_case_insensitive(client, isolated_files):
    """Приманка `admin` ловит и `ADMIN`, и `Admin`."""
    _set_honeytokens(isolated_files, ["admin"])
    ip = "203.0.113.71"
    resp = client.post(
        "/api/login",
        json={"username": "ADMIN", "password": "x"},
        environ_overrides={"REMOTE_ADDR": ip},
    )
    assert resp.status_code == 401
    after = client.get("/", environ_overrides={"REMOTE_ADDR": ip})
    assert after.status_code == 429


def test_real_login_still_works_with_honeytokens_set(client, isolated_files):
    """Наличие приманок не мешает нормальному входу настоящего пользователя."""
    _set_honeytokens(isolated_files, ["admin", "root", "backup"])
    ip = "203.0.113.72"
    resp = client.post(
        "/api/login",
        json={"username": TEST_USER, "password": TEST_PASSWORD},
        environ_overrides={"REMOTE_ADDR": ip},
    )
    assert resp.status_code == 200
    after = client.get("/", environ_overrides={"REMOTE_ADDR": ip})
    assert after.status_code != 429


def test_honeytoken_colliding_with_real_user_is_ignored(client, isolated_files):
    """Если приманкой по ошибке назвали реального пользователя — вход не ломается."""
    _set_honeytokens(isolated_files, [TEST_USER])
    ip = "203.0.113.73"
    resp = client.post(
        "/api/login",
        json={"username": TEST_USER, "password": TEST_PASSWORD},
        environ_overrides={"REMOTE_ADDR": ip},
    )
    assert resp.status_code == 200
    after = client.get("/", environ_overrides={"REMOTE_ADDR": ip})
    assert after.status_code != 429


def test_no_honeytokens_means_normal_behaviour(client, isolated_files):
    """Пустой/отсутствующий список приманок — обычная логика логина без бана."""
    ip = "203.0.113.74"
    resp = client.post(
        "/api/login",
        json={"username": "admin", "password": "x"},
        environ_overrides={"REMOTE_ADDR": ip},
    )
    assert resp.status_code == 401
    # Один промах по несуществующему логину не должен банить.
    after = client.get("/", environ_overrides={"REMOTE_ADDR": ip})
    assert after.status_code != 429


def test_honeytoken_ban_is_per_ip(client, isolated_files):
    """Бан по приманке не затрагивает другой IP."""
    _set_honeytokens(isolated_files, ["root"])
    client.post(
        "/api/login",
        json={"username": "root", "password": "x"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.75"},
    )
    resp = client.get("/", environ_overrides={"REMOTE_ADDR": "203.0.113.76"})
    assert resp.status_code == 302
