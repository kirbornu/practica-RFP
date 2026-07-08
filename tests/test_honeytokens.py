import json

import server


def _set_honeytokens(isolated_files, paths):
    """Дописывает список явных путей-ловушек в изолированный config.json."""
    cfg = isolated_files["config"]
    data = json.loads(cfg.read_text(encoding="utf-8"))
    data["honeytokens"] = paths
    cfg.write_text(json.dumps(data), encoding="utf-8")


def test_nonexistent_api_trips_and_bans(client):
    """Запрос к несуществующему /api/* — ловушка: 404 и мгновенный бан IP."""
    ip = "203.0.113.70"
    resp = client.get("/api/users", environ_overrides={"REMOTE_ADDR": ip})
    # Обезличенный 404 — ловушку не отличить от обычного «не найдено».
    assert resp.status_code == 404
    # IP уже забанен: следующий запрос ловит 429 ещё до формы входа.
    after = client.get("/", environ_overrides={"REMOTE_ADDR": ip})
    assert after.status_code == 429


def test_explicit_honeytoken_path_trips(client, isolated_files):
    """Явный путь-ловушка из конфига (напр. /wp-login.php) банит IP."""
    _set_honeytokens(isolated_files, ["/wp-login.php", "/.env"])
    ip = "203.0.113.71"
    resp = client.get("/wp-login.php", environ_overrides={"REMOTE_ADDR": ip})
    assert resp.status_code == 404
    after = client.get("/", environ_overrides={"REMOTE_ADDR": ip})
    assert after.status_code == 429


def test_honeytoken_path_is_case_insensitive(client, isolated_files):
    """Путь-ловушка ловит и /Admin, и /admin."""
    _set_honeytokens(isolated_files, ["/admin"])
    ip = "203.0.113.72"
    client.get("/ADMIN", environ_overrides={"REMOTE_ADDR": ip})
    after = client.get("/", environ_overrides={"REMOTE_ADDR": ip})
    assert after.status_code == 429


def test_real_api_endpoint_not_trapped(auth_client):
    """Настоящий API-эндпоинт работает как обычно — ловушка не срабатывает."""
    ip = "203.0.113.73"
    resp = auth_client.get("/api/config", environ_overrides={"REMOTE_ADDR": ip})
    assert resp.status_code == 200
    after = auth_client.get("/", environ_overrides={"REMOTE_ADDR": ip})
    assert after.status_code != 429


def test_wrong_method_on_real_path_not_trapped(auth_client):
    """Метод-mismatch (405) на реальном пути ловушкой не считается."""
    ip = "203.0.113.74"
    # /api/config существует только для GET/POST — PUT даёт 405, но это не ловушка.
    resp = auth_client.put("/api/config", environ_overrides={"REMOTE_ADDR": ip})
    assert resp.status_code == 405
    after = auth_client.get("/", environ_overrides={"REMOTE_ADDR": ip})
    assert after.status_code != 429


def test_non_api_404_does_not_trap(client):
    """Обычный не-/api 404 (напр. /favicon.ico от браузера) не банит."""
    ip = "203.0.113.75"
    client.get("/favicon.ico", environ_overrides={"REMOTE_ADDR": ip})
    after = client.get("/", environ_overrides={"REMOTE_ADDR": ip})
    assert after.status_code != 429


def test_public_port_has_no_honeytokens(client):
    """Публичный порт (тетрис) ловушки не трогают — бана нет."""
    ip = "203.0.113.76"
    client.get(
        "/api/users",
        environ_overrides={"REMOTE_ADDR": ip, "SERVER_PORT": "5001"},
    )
    # Тот же IP на приватном порту не забанен.
    after = client.get("/", environ_overrides={"REMOTE_ADDR": ip})
    assert after.status_code != 429


def test_honeytoken_ban_is_per_ip(client):
    """Бан по ловушке не затрагивает другой IP."""
    client.get("/api/secret", environ_overrides={"REMOTE_ADDR": "203.0.113.77"})
    resp = client.get("/", environ_overrides={"REMOTE_ADDR": "203.0.113.78"})
    assert resp.status_code == 302
