import server
from conftest import TEST_USER, TEST_PASSWORD

WRONG = {"username": TEST_USER, "password": "nope"}
RIGHT = {"username": TEST_USER, "password": TEST_PASSWORD}


def _fail_login(client, ip, n):
    for _ in range(n):
        client.post("/api/login", json=WRONG, environ_overrides={"REMOTE_ADDR": ip})


def test_ban_after_threshold(client):
    """После BAN_MAX_ATTEMPTS промахов IP банится и получает 429 ещё до логина."""
    ip = "203.0.113.50"
    _fail_login(client, ip, server.BAN_MAX_ATTEMPTS)
    resp = client.get("/", environ_overrides={"REMOTE_ADDR": ip})
    assert resp.status_code == 429


def test_not_banned_below_threshold(client):
    """На один промах меньше порога — бана нет (обычный редирект на логин)."""
    ip = "203.0.113.51"
    _fail_login(client, ip, server.BAN_MAX_ATTEMPTS - 1)
    resp = client.get("/", environ_overrides={"REMOTE_ADDR": ip})
    assert resp.status_code == 302


def test_ban_blocks_login_even_with_right_password(client):
    """Забаненному не поможет и верный пароль: 429 срабатывает раньше проверки."""
    ip = "203.0.113.52"
    _fail_login(client, ip, server.BAN_MAX_ATTEMPTS)
    resp = client.post("/api/login", json=RIGHT, environ_overrides={"REMOTE_ADDR": ip})
    assert resp.status_code == 429


def test_success_resets_counter(client):
    """Успешный вход обнуляет счётчик — накопленные промахи не приводят к бану."""
    ip = "203.0.113.53"
    _fail_login(client, ip, server.BAN_MAX_ATTEMPTS - 1)
    ok = client.post("/api/login", json=RIGHT, environ_overrides={"REMOTE_ADDR": ip})
    assert ok.status_code == 200
    # После сброса те же BAN_MAX-1 промахов снова не дотягивают до бана.
    _fail_login(client, ip, server.BAN_MAX_ATTEMPTS - 1)
    resp = client.get("/", environ_overrides={"REMOTE_ADDR": ip})
    assert resp.status_code != 429


def test_ban_is_per_ip(client):
    """Бан одного адреса не затрагивает другой."""
    _fail_login(client, "203.0.113.54", server.BAN_MAX_ATTEMPTS)
    resp = client.get("/", environ_overrides={"REMOTE_ADDR": "203.0.113.55"})
    assert resp.status_code == 302


def test_public_port_not_banned(client):
    """Публичный порт (тетрис) fail2ban не трогает — открыт даже забаненному IP."""
    ip = "203.0.113.56"
    _fail_login(client, ip, server.BAN_MAX_ATTEMPTS)
    resp = client.get(
        "/", environ_overrides={"REMOTE_ADDR": ip, "SERVER_PORT": "5001"}
    )
    assert resp.status_code == 200
