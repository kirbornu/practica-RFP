import json

from conftest import TEST_USER, TEST_PASSWORD


# --- Авторизация -------------------------------------------------------------

def test_api_requires_auth(client):
    """Без входа приватный API отвечает честным 401 (а не редиректом)."""
    resp = client.get("/api/rules")
    assert resp.status_code == 401


def test_page_redirects_to_login_when_anonymous(client):
    """Приватную страницу без входа отдаём редиректом на форму логина (302)."""
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_login_success(client):
    resp = client.post(
        "/api/login", json={"username": TEST_USER, "password": TEST_PASSWORD}
    )
    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True, "user": TEST_USER}


def test_login_wrong_password(client):
    resp = client.post(
        "/api/login", json={"username": TEST_USER, "password": "wrong"}
    )
    assert resp.status_code == 401
    assert "error" in resp.get_json()


def test_login_unknown_user(client):
    resp = client.post(
        "/api/login", json={"username": "nobody", "password": "x"}
    )
    assert resp.status_code == 401


def test_authenticated_access_after_login(auth_client):
    """С валидной сессией /api/rules доступен и возвращает список правил."""
    resp = auth_client.get("/api/rules")
    assert resp.status_code == 200
    assert "rules" in resp.get_json()


# --- Прокси: валидация ввода -------------------------------------------------

def test_add_proxy_valid(auth_client):
    resp = auth_client.post(
        "/api/proxies", json={"name": "srv", "address": "10.0.0.5", "port": "3128"}
    )
    assert resp.status_code == 200
    proxies = resp.get_json()["proxies"]
    assert any(p["address"] == "10.0.0.5:3128" for p in proxies)


def test_add_proxy_bad_ip(auth_client):
    resp = auth_client.post(
        "/api/proxies", json={"name": "srv", "address": "999.1.1.1", "port": "3128"}
    )
    assert resp.status_code == 400


def test_add_proxy_non_numeric_port(auth_client):
    resp = auth_client.post(
        "/api/proxies", json={"name": "srv", "address": "10.0.0.5", "port": "abc"}
    )
    assert resp.status_code == 400


def test_add_proxy_duplicate(auth_client):
    """Повторное добавление того же адреса — конфликт 409."""
    payload = {"name": "dup", "address": "10.0.0.9", "port": "3128"}
    assert auth_client.post("/api/proxies", json=payload).status_code == 200
    assert auth_client.post("/api/proxies", json=payload).status_code == 409


# --- Правила: полный жизненный цикл через API --------------------------------

def test_add_rule_writes_to_pac(auth_client, isolated_files):
    """Добавление правила через API должно реально появиться в PAC-файле
    и попасть в ответ GET /api/rules."""
    resp = auth_client.post(
        "/api/rules",
        json={"domain": "example.com", "type": "PROXY",
              "proxy_address": "192.0.2.11:3128"},
    )
    assert resp.status_code == 200

    # Проверяем реальный файл на диске (изолированный, во временной папке).
    pac_text = isolated_files["pac"].read_text(encoding="utf-8")
    assert "example.com" in pac_text

    # И что GET его теперь возвращает.
    rules = auth_client.get("/api/rules").get_json()["rules"]
    assert any(r["domain"] == "example.com" for r in rules)


def test_add_rule_invalid_domain(auth_client):
    resp = auth_client.post(
        "/api/rules",
        json={"domain": "не домен!!", "type": "PROXY",
              "proxy_address": "192.0.2.11:3128"},
    )
    assert resp.status_code == 400


def test_add_rule_duplicate_domain(auth_client):
    payload = {"domain": "dup.com", "type": "PROXY",
               "proxy_address": "192.0.2.11:3128"}
    assert auth_client.post("/api/rules", json=payload).status_code == 200
    # второй раз тот же домен — 409
    assert auth_client.post("/api/rules", json=payload).status_code == 409


def test_delete_rule(auth_client, isolated_files):
    """Полный цикл: добавили правило -> удалили -> его больше нет в файле."""
    auth_client.post(
        "/api/rules",
        json={"domain": "temp.com", "type": "PROXY",
              "proxy_address": "192.0.2.11:3128"},
    )
    resp = auth_client.post(
        "/api/rules/delete", json={"type": "PROXY", "domain": "temp.com"}
    )
    assert resp.status_code == 200
    pac_text = isolated_files["pac"].read_text(encoding="utf-8")
    assert "temp.com" not in pac_text


def test_delete_missing_rule_returns_404(auth_client):
    resp = auth_client.post(
        "/api/rules/delete", json={"type": "PROXY", "domain": "ghost.com"}
    )
    assert resp.status_code == 404


# --- УРОК 6: Порт-асимметрия (ключевое свойство безопасности) ---------------
#
# На публичном порту (5001) должен быть доступен ТОЛЬКО тетрис на "/".
# Всё остальное — /login, /logout, /api/* — отдаёт 404, будто не существует.
# Режим определяется реальным портом сокета (SERVER_PORT), который мы
# подменяем через environ_overrides — клиент в реальности подделать его не может.

PUBLIC = {"SERVER_PORT": "5001"}


def test_public_port_serves_root_without_auth(client):
    """На публичном порту "/" отдаётся без всякого логина (это тетрис)."""
    resp = client.get("/", environ_overrides=PUBLIC)
    assert resp.status_code == 200


def test_public_port_hides_api(client):
    """/api/* на публичном порту не существует -> 404, а не 401."""
    resp = client.get("/api/rules", environ_overrides=PUBLIC)
    assert resp.status_code == 404


def test_public_port_hides_login(client):
    """Даже страница логина на публичном порту скрыта (404)."""
    resp = client.get("/login", environ_overrides=PUBLIC)
    assert resp.status_code == 404


def test_public_port_blocks_login_api(client):
    """И залогиниться через публичный порт нельзя — /api/login там 404."""
    resp = client.post(
        "/api/login",
        json={"username": TEST_USER, "password": TEST_PASSWORD},
        environ_overrides=PUBLIC,
    )
    assert resp.status_code == 404
