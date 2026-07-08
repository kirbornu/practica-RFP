import os

import pytest

# Если requests не установлен — тесты пропускаются, а не рушат прогон.
requests = pytest.importorskip("requests")

BASE_URL = os.environ.get("SMOKE_BASE_URL")
PUBLIC_URL = os.environ.get("SMOKE_PUBLIC_URL")

pytestmark = [
    pytest.mark.smoke,
    pytest.mark.skipif(
        not BASE_URL,
        reason="SMOKE_BASE_URL не задан — smoke-тесты идут только по живому проду",
    ),
]

TIMEOUT = 10  # сек: прод должен отвечать быстро, иначе считаем это проблемой


# --- Приватный порт ----------------------------------------------
#
# На приватном порту может стоять access-list (config["allowed_ips"]): тогда
# запрос с невайтлистнутого IP получает 403 ещё до авторизации. Смок должен
# переживать оба режима — вайтлистнутый раннер (видит обычный auth-поток) и
# невайтлистнутый (видит 403). Главное свойство в любом случае: приватный порт
# не открыт анониму.

def _private_ip_blocked():
    """True, если приватный порт закрыт для нас access-list'ом (отдаёт 403).

    В этом режиме auth-специфичные проверки не имеют смысла — с нашего IP до
    формы входа и API просто не достучаться.
    """
    r = requests.get(BASE_URL + "/", allow_redirects=False, timeout=TIMEOUT)
    return r.status_code == 403


def test_private_root_alive_and_protected():
    """Прод жив и защищён: аноним получает редирект на /login, либо 403, если
    наш IP режет access-list. И то, и другое — «живой и не пускает наружу»."""
    r = requests.get(BASE_URL + "/", allow_redirects=False, timeout=TIMEOUT)
    assert r.status_code in (301, 302, 403)
    if r.status_code in (301, 302):
        assert "/login" in r.headers.get("Location", "")


def test_private_login_page_serves():
    """Страница входа отдаётся (200). Если наш IP закрыт access-list'ом —
    пропускаем: до /login с этого адреса не достучаться."""
    if _private_ip_blocked():
        pytest.skip("приватный порт закрыт access-list'ом для этого IP")
    r = requests.get(BASE_URL + "/login", timeout=TIMEOUT)
    assert r.status_code == 200


def test_private_api_requires_auth():
    """Приватный API без сессии недоступен: 401 (нужна авторизация) или 403
    (наш IP не в access-list). Открытым (2xx) он быть не должен."""
    r = requests.get(BASE_URL + "/api/rules", timeout=TIMEOUT)
    assert r.status_code in (401, 403)


# --- Публичный порт -------------------------------------------------

def _require_public():
    if not PUBLIC_URL:
        pytest.skip("SMOKE_PUBLIC_URL не задан")


def test_public_root_serves_without_auth():
    """Публичный порт отдаёт тетрис на "/" без логина (200)."""
    _require_public()
    r = requests.get(PUBLIC_URL + "/", timeout=TIMEOUT)
    assert r.status_code == 200


def test_public_port_hides_api():
    """Публичный порт прячет /api за 404 — свойство безопасности работает на проде."""
    _require_public()
    r = requests.get(PUBLIC_URL + "/api/rules", timeout=TIMEOUT)
    assert r.status_code == 404
