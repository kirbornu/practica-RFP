# conftest.py в корне репозитория.
#
# У этого файла две роли:
#
# 1. Само его присутствие в корне говорит pytest добавить корень проекта в
#    sys.path. Без этого тесты из папки tests/ не смогли бы сделать
#    `import server` — Python не нашёл бы модуль. Это стандартный приём.
#
# 2. Здесь живут "фикстуры" (fixture) — переиспользуемые заготовки для тестов.
#    Фикстуру подключают, просто указав её имя в аргументах тестовой функции;
#    pytest сам её вызовет и подставит результат.

import json

import pytest
from werkzeug.security import generate_password_hash

import server

# Учётка тест-пользователя. Пароль знаем в открытую только в тестах —
# в users.json лежит уже хеш.
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
    """Изолирует приложение от реальных данных.

    Каждый тест получает свежие config.json, users.json и PAC-файл во
    временной папке (tmp_path уникальна для теста). monkeypatch подменяет
    пути внутри server на эти временные файлы и АВТОМАТИЧЕСКИ откатывает
    подмену после теста — реальные файлы проекта не затрагиваются.

    Возвращает пути к созданным файлам, если тесту надо заглянуть в них.
    """
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


@pytest.fixture
def client(isolated_files):
    """Flask test client — «фейковый браузер», который дёргает эндпоинты
    напрямую в процессе, без реального сети/сервера.

    Зависит от isolated_files (указан в аргументах), поэтому к моменту
    создания клиента пути уже подменены на временные.
    """
    server.app.config.update(TESTING=True)
    # В проде cookie помечена Secure (только HTTPS). Тестовый http-клиент такую
    # cookie не вернул бы, и сессия бы «не прилипала» — на время тестов снимаем.
    server.app.config["SESSION_COOKIE_SECURE"] = False
    return server.app.test_client()


@pytest.fixture
def auth_client(client):
    """Уже залогиненный клиент — для тестов, которым нужен доступ к /api/*.

    Логинимся один раз здесь, дальше сессия держится в cookie-jar клиента.
    """
    resp = client.post(
        "/api/login",
        json={"username": TEST_USER, "password": TEST_PASSWORD},
    )
    assert resp.status_code == 200, "фикстура auth_client: логин не удался"
    return client
