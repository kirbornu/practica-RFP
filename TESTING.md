# Тестирование проекта

Памятка по автотестам и по тому, как они встроены в CI/CD-пайплайн.

## Пирамида тестирования

Тесты разложены по трём слоям — снизу вверх их меньше, но каждый дороже:

| Слой | Файл | Что проверяет | Скорость |
| --- | --- | --- | --- |
| Юнит | `tests/test_pac_parser.py` | чистые функции разбора/правки PAC (`parse_rules`, `insert_*`, `_remove_rule`, …) | мгновенно |
| API | `tests/test_api.py` | HTTP-эндпоинты Flask: авторизация, CRUD правил, порт-асимметрия | секунды |
| Smoke | `tests/test_smoke.py` | живой развёрнутый прод по HTTP | зависит от сети |

Идея: юнит-тестов много и они ловят баги логики; API-тесты проверяют цепочку
целиком; smoke — что прод реально поднялся после деплоя.

## Запуск локально

```bash
# один раз — зависимости приложения + тестов
pip install -r requirements.txt -r requirements-dev.txt

# все юнит + API тесты (smoke пропустятся — нет адреса прода)
pytest

# подробно, по одному тесту в строке
pytest -v

# только один файл / один тест
pytest tests/test_pac_parser.py
pytest tests/test_api.py::test_login_success

# только smoke — по конкретному стенду
SMOKE_BASE_URL=http://192.0.2.20:8080 \
SMOKE_PUBLIC_URL=http://192.0.2.20:8090 \
pytest tests/test_smoke.py -v
```

`pytest.ini` задаёт `testpaths=tests` и регистрирует маркер `smoke`.
Фикстуры (`client`, `auth_client`, `isolated_files`) лежат в `conftest.py`;
они изолируют тесты от реальных `config.json` / `users.json` / PAC-файла,
подменяя пути на временные (`tmp_path` + `monkeypatch`).

## Как тесты встроены в пайплайн

Две ветки прогонов:

- **`.gitea/workflows/test.yml`** — на каждый пуш в ветку и на каждый PR
  (кроме `master`): юнит + API. Быстрый фидбэк ещё до слияния.
- **`.gitea/workflows/deploy.yml`** — на пуш в `master`, цепочка с `needs:`:

  ```
  test ──► build ──► deploy ──► smoke
  ```

  `build` зависит от `test` → красные тесты останавливают сборку, и битый код
  не попадает на прод. После деплоя `smoke` бьёт по живому проду
  (`192.0.2.20:8080` и `:8090`) и проверяет, что он поднялся и защищён.

Джобы `test` и `smoke` идут на раннере с меткой `tests` — это наша Debian-ВМ.
Джобы `build`/`deploy` — на прежнем раннере `ubuntu-latest` (у него есть Docker
и SSH-доступ на прод).

## Настройка Debian-ВМ как Gitea Actions runner

На новой Debian-виртуалке (метка `tests`):

```bash
# 1. Базовые пакеты: git, python, pip нужны шагам джоба
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv curl

# 2. Скачать act_runner (агент Gitea Actions); версию подставить актуальную
curl -L -o act_runner \
  https://dl.gitea.com/act_runner/act_runner-linux-amd64
chmod +x act_runner

# 3. Взять токен регистрации в Gitea:
#    админка → Site Administration → Actions → Runners → Create new Runner,
#    ЛИБО на уровне репозитория: Settings → Actions → Runners.

# 4. Зарегистрировать раннер с меткой tests, исполняющей джобы прямо на хосте
#    (host — без Docker; поэтому git/python и ставим системно на шаге 1):
./act_runner register \
  --no-interactive \
  --instance http://192.0.2.41:3000 \
  --token <ТОКЕН_ИЗ_ШАГА_3> \
  --name debian-tests \
  --labels tests:host

# 5. Запустить как демон (для постоянной работы оформить в systemd-сервис)
./act_runner daemon
```

После регистрации раннер появится в Gitea со статусом *Idle* и меткой `tests`,
и джобы с `runs-on: tests` поедут на него.

> Метка `tests:host` означает «выполнять шаги напрямую на этой машине». Поэтому
> `git` и `python3`/`pip` должны быть установлены системно (шаг 1). Альтернатива —
> `tests:docker://python:3.11` (каждый джоб в контейнере), но тогда раннеру нужен
> Docker; для выделенной тест-ВМ вариант `host` проще и прозрачнее.

## Как добавить свой тест

1. Открой нужный файл в `tests/` (или создай новый `tests/test_*.py`).
2. Напиши функцию `def test_что_проверяем():` и внутри — `assert <условие>`.
3. Запусти `pytest -v` и убедись, что она зелёная.
4. Закоммить — CI прогонит её автоматически.
