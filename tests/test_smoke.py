"""Smoke-тесты (верх пирамиды): проверка УЖЕ РАЗВЁРНУТОГО прода по HTTP.

В отличие от юнит/API-тестов, эти бьют по живому серверу по сети через
библиотеку requests. Их задача — поймать проблемы деплоя, а не логики:
контейнер не поднялся, порт не проброшен, Redis недоступен и т.п.

Адрес прода берётся из переменных окружения:
    SMOKE_BASE_URL    приватный порт, напр. http://192.0.2.20:8080
    SMOKE_PUBLIC_URL  публичный порт,  напр. http://192.0.2.20:8090

Если SMOKE_BASE_URL не задан — все тесты этого файла ПРОПУСКАЮТСЯ (skip),
поэтому обычный `pytest` на машине разработчика их не запускает и не падает.
Запускаются они в пайплайне ПОСЛЕ деплоя (см. .gitea/workflows/deploy.yml).

Запуск вручную:
    SMOKE_BASE_URL=http://192.0.2.20:8080 \
    SMOKE_PUBLIC_URL=http://192.0.2.20:8090 \
    pytest tests/test_smoke.py -v
"""

import os

import pytest

# Если requests не установлен — тесты пропускаются, а не рушат прогон.
requests = pytest.importorskip("requests")

BASE_URL = os.environ.get("SMOKE_BASE_URL")
PUBLIC_URL = os.environ.get("SMOKE_PUBLIC_URL")

# pytestmark применяет маркеры/условия КО ВСЕМ тестам файла сразу:
#   - помечаем их маркером smoke (можно фильтровать: pytest -m smoke);
#   - пропускаем весь файл, если не задан адрес прода.
pytestmark = [
    pytest.mark.smoke,
    pytest.mark.skipif(
        not BASE_URL,
        reason="SMOKE_BASE_URL не задан — smoke-тесты идут только по живому проду",
    ),
]

TIMEOUT = 10  # сек: прод должен отвечать быстро, иначе считаем это проблемой


# --- Приватный порт (редактор) ----------------------------------------------

def test_private_root_redirects_anonymous_to_login():
    """Прод жив и защищён: "/" для анонима отдаёт редирект на /login."""
    r = requests.get(BASE_URL + "/", allow_redirects=False, timeout=TIMEOUT)
    assert r.status_code in (301, 302)
    assert "/login" in r.headers.get("Location", "")


def test_private_login_page_serves():
    """Страница входа отдаётся (200) — статика на месте."""
    r = requests.get(BASE_URL + "/login", timeout=TIMEOUT)
    assert r.status_code == 200


def test_private_api_requires_auth():
    """Приватный API без сессии отвечает 401 — авторизация работает на проде."""
    r = requests.get(BASE_URL + "/api/rules", timeout=TIMEOUT)
    assert r.status_code == 401


# --- Публичный порт (тетрис) -------------------------------------------------

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
