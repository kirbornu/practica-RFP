import json

from conftest import TEST_USER, TEST_PASSWORD


def _set_allowed_ips(isolated_files, ips):
    """Дописывает allowed_ips в тот же config.json, что читает приложение."""
    cfg_path = isolated_files["config"]
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["allowed_ips"] = ips
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")


# --- Фильтр выключен (ключа нет / список пуст) -------------------------------

def test_no_allowed_ips_allows_everyone(client):
    """Без ключа allowed_ips фильтр выключен — доступ открыт (обычный 302 на /)."""
    resp = client.get("/", environ_overrides={"REMOTE_ADDR": "203.0.113.99"})
    assert resp.status_code == 302  # редирект на логин, но не 403


def test_empty_allowed_ips_allows_everyone(client, isolated_files):
    """Пустой allowed_ips = выключенный фильтр (opt-in), а не «запретить всех»."""
    _set_allowed_ips(isolated_files, [])
    resp = client.get("/", environ_overrides={"REMOTE_ADDR": "203.0.113.99"})
    assert resp.status_code == 302


# --- Одиночные адреса --------------------------------------------------------

def test_allowed_ip_passes(client, isolated_files):
    _set_allowed_ips(isolated_files, ["203.0.113.7"])
    resp = client.get("/", environ_overrides={"REMOTE_ADDR": "203.0.113.7"})
    assert resp.status_code == 302  # прошёл фильтр, дальше обычная логика


def test_disallowed_ip_blocked(client, isolated_files):
    _set_allowed_ips(isolated_files, ["203.0.113.7"])
    resp = client.get("/", environ_overrides={"REMOTE_ADDR": "203.0.113.8"})
    assert resp.status_code == 403


# --- Подсети (CIDR) ----------------------------------------------------------

def test_cidr_range_allows_member(client, isolated_files):
    _set_allowed_ips(isolated_files, ["198.51.100.0/24"])
    resp = client.get("/", environ_overrides={"REMOTE_ADDR": "198.51.100.42"})
    assert resp.status_code == 302


def test_cidr_range_blocks_outsider(client, isolated_files):
    _set_allowed_ips(isolated_files, ["198.51.100.0/24"])
    resp = client.get("/", environ_overrides={"REMOTE_ADDR": "198.51.101.42"})
    assert resp.status_code == 403


# --- Фильтр действует до авторизации и на всех маршрутах ----------------------

def test_blocked_before_auth_on_api(client, isolated_files):
    """С запрещённого IP даже /api/* отдаёт 403, а не 401 — фильтр раньше авторизации."""
    _set_allowed_ips(isolated_files, ["203.0.113.7"])
    resp = client.get("/api/rules", environ_overrides={"REMOTE_ADDR": "10.0.0.1"})
    assert resp.status_code == 403


def test_blocked_before_login(client, isolated_files):
    """Залогиниться с запрещённого IP нельзя — /api/login тоже под фильтром."""
    _set_allowed_ips(isolated_files, ["203.0.113.7"])
    resp = client.post(
        "/api/login",
        json={"username": TEST_USER, "password": TEST_PASSWORD},
        environ_overrides={"REMOTE_ADDR": "10.0.0.1"},
    )
    assert resp.status_code == 403


def test_public_port_also_filtered(client, isolated_files):
    """Публичный порт (тетрис) тоже закрыт для чужих IP: «подключаться» нельзя вообще."""
    _set_allowed_ips(isolated_files, ["203.0.113.7"])
    resp = client.get(
        "/", environ_overrides={"REMOTE_ADDR": "10.0.0.1", "SERVER_PORT": "5001"}
    )
    assert resp.status_code == 403


def test_x_forwarded_for_is_honored(client, isolated_files):
    """За прокси реальный IP берётся из X-Forwarded-For (ProxyFix), его и проверяем."""
    _set_allowed_ips(isolated_files, ["203.0.113.7"])
    # remote_addr сокета — «прокси», но клиентский IP из XFF разрешён.
    ok = client.get(
        "/",
        headers={"X-Forwarded-For": "203.0.113.7"},
        environ_overrides={"REMOTE_ADDR": "10.0.0.1"},
    )
    assert ok.status_code == 302
    # А чужой XFF-адрес блокируется.
    blocked = client.get(
        "/",
        headers={"X-Forwarded-For": "203.0.113.8"},
        environ_overrides={"REMOTE_ADDR": "10.0.0.1"},
    )
    assert blocked.status_code == 403


def test_bad_entry_is_skipped_not_fatal(client, isolated_files):
    """Мусорная запись в allowed_ips пропускается, валидная — продолжает работать."""
    _set_allowed_ips(isolated_files, ["не-ip", "203.0.113.7"])
    ok = client.get("/", environ_overrides={"REMOTE_ADDR": "203.0.113.7"})
    assert ok.status_code == 302
    blocked = client.get("/", environ_overrides={"REMOTE_ADDR": "203.0.113.8"})
    assert blocked.status_code == 403
