import ipaddress
import json
import os
import re
import secrets
import sys
import threading
import time
from datetime import datetime, timedelta
from flask import (
    Flask, request, jsonify, send_from_directory,
    session, redirect, url_for,
)
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import NotFound
from flask_session import Session
import redis

app = Flask(__name__)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
CONFIG_FILE = os.environ.get("CONFIG_FILE", "config.json")
USERS_FILE = os.environ.get("USERS_FILE", "users.json")

# --- Авторизация / сессии ---
# SECRET_KEY нужен для подписи cookie-сессий. Без него при перезапуске ключ
# меняется и всех разлогинивает — поэтому в проде задавайте его через env.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
if not os.environ.get("SECRET_KEY"):
    print("ВНИМАНИЕ: SECRET_KEY не задан — сессии не переживут перезапуск. "
          "Задайте переменную окружения SECRET_KEY в проде.")

# Приложение доступно извне → cookie только по HTTPS и без доступа из JS.
# Для локальной отладки по http можно выставить COOKIE_SECURE=false.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() != "false",
)

# --- Хранилище сессий ---
# В проде сессии храним на сервере в Redis: у клиента в cookie лежит только
# подписанный идентификатор сессии, а сами данные (кто вошёл) — в Redis.
# Это даёт серверный logout, единое хранилище на все воркеры gunicorn и
# отсутствие приватных данных в самой cookie.
# Если REDIS_URL не задан — откатываемся на обычные подписанные cookie-сессии
# Flask (годится только для локальной отладки).
REDIS_URL = os.environ.get("REDIS_URL")
if REDIS_URL:
    app.config.update(
        SESSION_TYPE="redis",
        SESSION_REDIS=redis.from_url(REDIS_URL),
        SESSION_PERMANENT=False,
        SESSION_USE_SIGNER=True,
        SESSION_KEY_PREFIX="prct:session:",
    )
    Session(app)
else:
    print("ВНИМАНИЕ: REDIS_URL не задан — используются клиентские cookie-сессии. "
          "Для прода задайте REDIS_URL (redis://redis:6379/0).")

# --- fail2ban: временная блокировка IP после серии неудачных входов ---
# Считаем неудачные попытки логина по IP: после BAN_MAX_ATTEMPTS попыток за окно
# BAN_WINDOW секунд адрес блокируется на BAN_TIME секунд (в ответ 429). Состояние
# держим в Redis — оно общее на все воркеры gunicorn. Без Redis откатываемся на
# in-memory (годится только для локального однопроцессного запуска: между
# воркерами счётчики не делятся).
BAN_MAX_ATTEMPTS = int(os.environ.get("BAN_MAX_ATTEMPTS", "5"))
BAN_WINDOW = int(os.environ.get("BAN_WINDOW", "300"))
BAN_TIME = int(os.environ.get("BAN_TIME", "900"))

_ban_redis = app.config.get("SESSION_REDIS")  # тот же клиент, что и для сессий
_ban_mem = {}          # {ip: {"fails": [ts, ...], "until": ts}} — фолбэк без Redis
_ban_lock = threading.Lock()

# Эндпоинты, доступные без входа (на приватном порту — до авторизации).
PUBLIC_ENDPOINTS = {"login_page", "login", "static"}

# --- Асимметрия по портам ---
# Приложение слушает несколько портов (см. gunicorn.conf.py -> bind).
# «Публичные» порты работают без авторизации и показывают только тетрис:
# редактор и все /api/* там недоступны. Различаем режим по РЕАЛЬНОМУ порту
# сокета (SERVER_PORT из WSGI-environ) — его, в отличие от заголовка Host,
# клиент подделать не может (важно: ProxyFix перезаписывает Host, но не порт).
PUBLIC_PORTS = set(
    p.strip() for p in os.environ.get("PUBLIC_PORTS", "5001").split(",") if p.strip()
)

# Что разрешено на публичном порту: только корень (отдаёт тетрис) и статика.
# Всё остальное (в т.ч. /login, /logout, /api/*) отдаёт 404 — снаружи их как
# будто не существует.
PUBLIC_ALLOWED_ENDPOINTS = {"home", "static"}


def is_public_request():
    """True, если запрос пришёл на «публичный» (безавторизационный) порт."""
    return request.environ.get("SERVER_PORT") in PUBLIC_PORTS


def parse_allowed_networks(allowed_ips):
    """Преобразует список строк config["allowed_ips"] в объекты ip_network.

    Поддерживаются одиночные адреса и подсети (CIDR), IPv4 и IPv6.
    Некорректные записи пропускаются с предупреждением, а не роняют запрос.
    """
    networks = []
    for item in allowed_ips or []:
        try:
            networks.append(ipaddress.ip_network(str(item).strip(), strict=False))
        except ValueError:
            print(f"ВНИМАНИЕ: некорректная запись в allowed_ips, пропущена: {item!r}")
    return networks


def is_ip_allowed(remote_addr, networks):
    """True, если remote_addr входит хотя бы в одну сеть из networks.

    Пустой networks означает «фильтр выключен» → разрешаем всех.
    """
    if not networks:
        return True
    if not remote_addr:
        return False
    try:
        ip = ipaddress.ip_address(remote_addr)
    except ValueError:
        return False
    return any(ip in net for net in networks)


def _ban_key(ip):
    return f"prct:fail2ban:ban:{ip}"


def _attempts_key(ip):
    return f"prct:fail2ban:att:{ip}"


def is_banned(ip):
    """True, если IP сейчас заблокирован после серии неудачных входов."""
    if not ip:
        return False
    if _ban_redis is not None:
        return bool(_ban_redis.exists(_ban_key(ip)))
    with _ban_lock:
        rec = _ban_mem.get(ip)
        return bool(rec and rec.get("until", 0) > time.time())


def ban_expires_at(ip):
    """Момент снятия бана как datetime с локальным часовым поясом, или None.

    С Redis берём остаток TTL ключа бана, без Redis — поле until из in-memory
    записи. Возвращаемый datetime «осознаёт» часовой пояс сервера (astimezone),
    чтобы показать пользователю время снятия блокировки в человекочитаемом виде.
    """
    if not ip:
        return None
    if _ban_redis is not None:
        ttl = _ban_redis.ttl(_ban_key(ip))
        if ttl is None or ttl < 0:
            return None
        return datetime.now().astimezone() + timedelta(seconds=ttl)
    with _ban_lock:
        rec = _ban_mem.get(ip)
        until = rec.get("until", 0) if rec else 0
    if until <= 0:
        return None
    return datetime.fromtimestamp(until).astimezone()


def ban_ip(ip):
    """Немедленно блокирует IP на BAN_TIME секунд, без накопления попыток.

    Используется как порогом fail2ban (после серии промахов), так и honeytoken'ами
    (сразу, с первой же попытки под логином-приманкой).
    """
    if not ip:
        return
    if _ban_redis is not None:
        _ban_redis.set(_ban_key(ip), "1", ex=BAN_TIME)
        _ban_redis.delete(_attempts_key(ip))
        return
    with _ban_lock:
        rec = _ban_mem.setdefault(ip, {"fails": [], "until": 0})
        rec["until"] = time.time() + BAN_TIME
        rec["fails"] = []


def register_login_failure(ip):
    """Учитывает неудачную попытку входа; при превышении порога — банит IP."""
    if not ip:
        return
    if _ban_redis is not None:
        n = _ban_redis.incr(_attempts_key(ip))
        if n == 1:
            # Первый промах в серии — заводим окно, внутри которого копятся попытки.
            _ban_redis.expire(_attempts_key(ip), BAN_WINDOW)
        if n >= BAN_MAX_ATTEMPTS:
            ban_ip(ip)
        return
    with _ban_lock:
        now = time.time()
        rec = _ban_mem.setdefault(ip, {"fails": [], "until": 0})
        rec["fails"] = [t for t in rec["fails"] if t > now - BAN_WINDOW]
        rec["fails"].append(now)
        if len(rec["fails"]) >= BAN_MAX_ATTEMPTS:
            rec["until"] = now + BAN_TIME
            rec["fails"] = []


def reset_login_failures(ip):
    """Сбрасывает счётчик неудач после успешного входа."""
    if not ip:
        return
    if _ban_redis is not None:
        _ban_redis.delete(_attempts_key(ip))
        return
    with _ban_lock:
        _ban_mem.pop(ip, None)


# --- honeytokens: ловушки на несуществующие эндпоинты ---
# Идея: легитимный клиент (редактор) ходит только по известному набору
# маршрутов. Запрос к НЕсуществующему API-эндпоинту (например /api/users,
# /api/admin, /api/v1/...) — явный признак сканирования/подбора: реального
# маршрута нет, а путь ведёт в /api/. Такой IP банится сразу (тем же механизмом,
# что и fail2ban), а в лог пишется тревога. Дополнительно можно перечислить
# явные пути-ловушки в config["honeytokens"] (напр. /wp-login.php, /.env,
# /.git/config) — популярная приманка для автосканеров. Ответ клиенту — обычный
# 404, чтобы ловушку нельзя было отличить от заурядного «не найдено».

# Префикс, под которым живёт API: любой несуществующий путь под ним — ловушка.
API_PREFIX = "/api/"


def load_honeytoken_paths():
    """Множество явных путей-ловушек из config["honeytokens"].

    Сравнение по точному пути (с ведущим слэшем), без учёта регистра — сканеры
    пробуют и /Admin, и /admin. Пустые записи отбрасываем.
    """
    paths = load_config().get("honeytokens", [])
    result = set()
    for p in paths:
        p = str(p).strip()
        if p:
            norm = ("/" + p.strip("/")).lower() or "/"
            result.add(norm)
    return result


def is_honeytoken_request():
    """True, если текущий запрос попал в ловушку honeytoken.

    Триггерит на: (1) явный путь-ловушку из конфига; (2) несуществующий
    эндпоинт под /api/ — реального маршрута нет (routing → 404 NotFound), а путь
    ведёт в API. Метод-mismatch (405) на реальном пути ловушкой не считаем.
    """
    path = (request.path or "").rstrip("/") or "/"
    if path.lower() in load_honeytoken_paths():
        return True
    if request.path.startswith(API_PREFIX) and isinstance(
        request.routing_exception, NotFound
    ):
        return True
    return False


# --- Страница блокировки ---
# Один общий шаблон ban.html на два повода отказа: access-list (IP вне
# allowed_ips) и fail2ban (IP в prct:fail2ban:ban — как после серии промахов,
# так и после honeytoken'а). Текст и HTTP-код различаются, вёрстка — общая.
PUBLIC_PORT_LINK = os.environ.get("PUBLIC_PORT_LINK", "8090")


def _public_port_link():
    """Абсолютная ссылка на публичный порт (тетрис) на том же хосте."""
    host = (request.host or "").split(":", 1)[0] or request.host
    return f"{request.scheme}://{host}:{PUBLIC_PORT_LINK}/"


def render_ban_page(variant, status):
    """Отдаёт ban.html с текстом под конкретный повод блокировки.

    variant="acl"     — IP не входит в allowed_ips (нет доступа к порту);
    variant="fail2ban" — IP забанен (показываем время снятия блокировки).
    IP-адрес и время подставляются в шаблон; HTTP-код сохраняем прежним
    (403 для acl, 429 для fail2ban), чтобы не менять контракт для тестов/клиентов.
    """
    ip = request.remote_addr or ""
    port_link = f'<a href="{escape(_public_port_link())}">портом {escape(PUBLIC_PORT_LINK)}</a>'
    if variant == "fail2ban":
        expires = ban_expires_at(ip)
        when = expires.strftime("%d.%m.%Y %H:%M:%S %Z") if expires else "позже"
        message = (
            f"Доступ к этому был заблокирован для Вас. "
            f"Блокировка закончится {escape(when)}. "
            f"Можете воспользоваться {port_link} или обратитесь к системному "
            f"администратору."
        )
    else:
        message = (
            f"Ваш IP-адрес не имеет доступа к этому порту. "
            f"Можете воспользоваться {port_link} или обратитесь к системному "
            f"администратору."
        )
    with open(os.path.join(BASE_DIR, "ban.html"), "r", encoding="utf-8") as f:
        html = f.read()
    html = html.replace("__BAN_MESSAGE__", message)
    html = html.replace("__BAN_IP__", str(escape(ip)))
    return html, status


@app.before_request
def enforce_ip_access():
    # Access-list действует только на приватных портах (редактор + API).
    # Публичный порт (тетрис) остаётся открытым для всех — он по замыслу
    # доступен без ограничений, поэтому здесь сразу выходим.
    if is_public_request():
        return
    # На приватном порту пускаем только с адресов из config["allowed_ips"].
    # Проверка идёт до авторизации, поэтому закрывает и редактор, и форму входа,
    # и все /api/*. Пустой/отсутствующий список = фильтр выключен (allow-all),
    # чтобы опечатка в конфиге не отрезала доступ целиком. request.remote_addr —
    # реальный IP клиента: ProxyFix уже подставил его из X-Forwarded-For.
    networks = parse_allowed_networks(load_config().get("allowed_ips", []))
    if not is_ip_allowed(request.remote_addr, networks):
        return render_ban_page("acl", 403)


@app.before_request
def enforce_ban():
    # fail2ban — тоже только приватные порты (там живёт логин). Публичный тетрис
    # не трогаем, как и access-list. Забаненный IP получает 429 ещё до формы
    # входа, так что подобрать пароль перебором нельзя.
    if is_public_request():
        return
    if is_banned(request.remote_addr):
        return render_ban_page("fail2ban", 429)


@app.before_request
def enforce_honeytokens():
    # honeytokens — тоже только приватные порты (как ACL и fail2ban). Публичный
    # тетрис не трогаем: там нет API и ловушек. Проверяем до guard, чтобы запрос
    # к несуществующему API забанил сканера, а не просто получил 401/404.
    if is_public_request():
        return
    if is_honeytoken_request():
        ip = request.remote_addr
        ban_ip(ip)
        app.logger.warning(
            "HONEYTOKEN: обращение к ловушке %s %s с IP %s — IP заблокирован",
            request.method, request.path, ip,
        )
        # Обезличенный 404: ловушку нельзя отличить от обычного «не найдено».
        return jsonify({"error": "Не найдено"}), 404


def load_users():
    """Возвращает {логин: хеш_пароля}. Пусто, если файла нет."""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)


@app.before_request
def guard():
    # Публичный порт: авторизация не нужна, но доступен только белый список
    # (домашняя страница в урезанном виде + тетрис). Всё прочее — 404, чтобы
    # редактор и API снаружи вообще не проявлялись.
    if is_public_request():
        if request.endpoint in PUBLIC_ALLOWED_ENDPOINTS:
            return
        return jsonify({"error": "Не найдено"}), 404

    # Приватный порт: обычная авторизация.
    if request.endpoint in PUBLIC_ENDPOINTS:
        return
    if session.get("user"):
        return
    # API отвечает честным 401, страницы — редиректом на форму входа.
    if request.path.startswith("/api/"):
        return jsonify({"error": "Требуется авторизация"}), 401
    return redirect(url_for("login_page"))


def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"routing_file": "", "proxies": []}


def save_config(config):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


def get_editable_section(content):
    """Возвращает часть файла до //constants (или весь файл если маркера нет)."""
    match = re.search(r'\n\s*//constants', content)
    if match:
        return content[:match.start()], content[match.start():]
    return content, ""


def get_existing_domains(content):
    return set(re.findall(r'shExpMatch\((?:host|url),\s*["\']([^"\'*][^"\']*)["\']', content))


def _scan_if_blocks(content):
    """Идёт по тексту и выдаёт (start, end, condition, body) для каждого if(...){...}.

    start — позиция 'if', end — позиция сразу после закрывающей '}'.
    Скобки и фигурные скобки считаются честно, по балансу вложенности —
    поэтому одинаково работает и для однострочных, и для многострочных блоков.
    """
    i = 0
    n = len(content)
    while i < n:
        m = re.search(r'\bif\s*\(', content[i:])
        if not m:
            break

        start = i + m.start()
        # Находим закрывающую ) условия — считаем вложенность
        depth = 0
        j = i + m.end() - 1  # позиция открывающей (
        while j < n:
            if content[j] == '(':
                depth += 1
            elif content[j] == ')':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= n:
            break

        condition = content[start:j + 1]

        # Находим тело { ... }
        k = j + 1
        while k < n and content[k] in ' \t\n':
            k += 1

        if k < n and content[k] == '{':
            depth = 0
            body_start = k
            while k < n:
                if content[k] == '{':
                    depth += 1
                elif content[k] == '}':
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            body = content[body_start:k + 1]
            end = k + 1
        else:
            i = start + 1
            continue

        yield start, end, condition, body
        i = end


def parse_rules(content):
    rules = []
    for _, _, condition, body in _scan_if_blocks(content):
        rule = _parse_if_block(condition, body)
        if rule:
            rules.append(rule)
    return rules


def _parse_if_block(condition, body):
    # Определяем тип по return в теле
    proxy_m = re.search(r'return\s*["\']PROXY\s+([\w.\-]+:\d+)["\']', body)
    direct_m = re.search(r'return\s*["\']DIRECT["\']', body)

    if proxy_m:
        # Для PROXY берём чистый домен — паттерн без ведущей звёздочки,
        # чтобы не словить вторую ветку shExpMatch(host, "*.domain").
        domain_m = re.search(
            r'shExpMatch\(\s*(?:url|host)\s*,\s*["\']([^"\'*][^"\']*)["\']',
            condition,
        )
        if not domain_m:
            return None
        return {"domain": domain_m.group(1), "type": "PROXY", "proxy": proxy_m.group(1)}

    if direct_m:
        # Для DIRECT берём полный паттерн целиком — ведущая звёздочка разрешена
        # (правила вида "*//domain/*").
        pattern_m = re.search(
            r'shExpMatch\(\s*(?:url|host)\s*,\s*["\']([^"\']+)["\']',
            condition,
        )
        if not pattern_m:
            return None
        return {"domain": pattern_m.group(1), "type": "DIRECT", "proxy": None}

    return None


def _remove_rule(content, predicate):
    """Удаляет первый if-блок, для которого predicate(rule) истинно.

    Использует тот же честный обход скобок, что и парсер, поэтому корректно
    вырезает и многострочные PROXY-блоки, и однострочные DIRECT.
    Возвращает (новый_контент, удалено?).
    """
    for start, end, condition, body in _scan_if_blocks(content):
        rule = _parse_if_block(condition, body)
        if rule and predicate(rule):
            # Поглощаем ведущие пробелы/табы и один перенос строки,
            # чтобы не оставлять пустую строку на месте правила.
            s = start
            while s > 0 and content[s - 1] in ' \t':
                s -= 1
            if s > 0 and content[s - 1] == '\n':
                s -= 1
            return content[:s] + content[end:], True
    return content, False


def insert_proxy_rule(content, domain, proxy_address):
    rule = (
        f'\n    if (shExpMatch(host, "{domain}") || shExpMatch(host, "*.{domain}")) {{\n'
        f'        return "PROXY {proxy_address}";\n'
        f'    }}\n'
    )
    match = re.search(r'\n(\s*)//PROXY', content)
    if match:
        pos = match.end()
        return content[:pos] + rule + content[pos:]
    match = re.search(r'(\$Proxy\s*=\s*[^\n]+\n)', content)
    if match:
        pos = match.end()
        return content[:pos] + rule + content[pos:]
    match = re.search(r'\{\s*\n', content)
    if match:
        pos = match.end()
        return content[:pos] + rule + content[pos:]
    return rule + content


def insert_direct_rule(content, domain):
    rule = f'\n\tif (shExpMatch(url, "*//{domain}/*")) {{return "DIRECT";}}'
    match = re.search(r'\n(\s*)//DIRECT', content)
    if match:
        pos = match.end()
        return content[:pos] + rule + content[pos:]
    match = re.search(r'(\$Proxy\s*=\s*[^\n]+\n)', content)
    if match:
        pos = match.end()
        return content[:pos] + rule + '\n' + content[pos:]
    match = re.search(r'\{\s*\n', content)
    if match:
        pos = match.end()
        return content[:pos] + rule + '\n' + content[pos:]
    return content + rule


# --- API ---

@app.route("/login")
def login_page():
    return send_from_directory(BASE_DIR, "login.html")


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    ip = request.remote_addr
    pw_hash = load_users().get(username)
    if not pw_hash or not check_password_hash(pw_hash, password):
        register_login_failure(ip)
        return jsonify({"error": "Неверный логин или пароль"}), 401
    reset_login_failures(ip)
    session["user"] = username
    return jsonify({"ok": True, "user": username})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/")
def home():
    # Каждый порт отдаёт свою страницу на корне:
    #   публичный (8090) — тетрис без авторизации;
    #   приватный (8080) — редактор (сюда before_request требует вход).
    if is_public_request():
        return send_from_directory(BASE_DIR, "tetris.html")
    return send_from_directory(BASE_DIR, "editor.html")


@app.route("/api/config", methods=["GET"])
def get_config():
    return jsonify(load_config())


@app.route("/api/config", methods=["POST"])
def set_config():
    data = request.get_json()
    config = load_config()
    path = data.get("routing_file", "").strip()
    if not path:
        return jsonify({"error": "Путь не может быть пустым"}), 400
    config["routing_file"] = path
    save_config(config)
    return jsonify({"ok": True})


@app.route("/api/proxies", methods=["GET"])
def get_proxies():
    return jsonify(load_config().get("proxies", []))


@app.route("/api/proxies", methods=["POST"])
def add_proxy():
    data = request.get_json()
    name = data.get("name", "").strip()
    address = data.get("address", "").strip()
    port = data.get("port", "").strip()
    if not name or not address or not port:
        return jsonify({"error": "Нужны название, адрес и порт"}), 400
    ip = address + ':' + port
    # Валидация IP (v4) и порта
    if not port.isdigit():
        return jsonify({"error": "Порт должен быть числом"}), 400
    ip_only = address
    port_int = int(port)
    octets = ip_only.split('.')
    if len(octets) != 4 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
        return jsonify({"error": "Неверный IP-адрес. Пример: 192.168.1.1"}), 400
    if not (1 <= port_int <= 65535):
        return jsonify({"error": "Порт должен быть от 1 до 65535"}), 400
    config = load_config()
    proxies = config.get("proxies", [])
    if any(p["address"] == ip for p in proxies):
        return jsonify({"error": "Такой прокси уже есть"}), 409
    proxies.append({"name": name, "address": ip})
    config["proxies"] = proxies
    save_config(config)
    return jsonify({"ok": True, "proxies": proxies})


@app.route("/api/proxies/<int:idx>", methods=["DELETE"])
def delete_proxy(idx):
    config = load_config()
    proxies = config.get("proxies", [])
    if idx < 0 or idx >= len(proxies):
        return jsonify({"error": "Индекс вне диапазона"}), 404

    proxy_address = proxies[idx]["address"]

    # Проверяем, используется ли адрес в PAC-файле
    path = config.get("routing_file", "")
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            pac_content = f.read()
        editable, _ = get_editable_section(pac_content)
        rules = parse_rules(editable)
        using = [r["domain"] for r in rules if r.get("proxy") == proxy_address]
        if using:
            domains_str = ", ".join(using[:5])
            if len(using) > 5:
                domains_str += f" и ещё {len(using) - 5}"
            return jsonify({
                "error": f"Нельзя удалить: адрес используется в правилах ({domains_str})"
            }), 409

    proxies.pop(idx)
    config["proxies"] = proxies
    save_config(config)
    return jsonify({"ok": True, "proxies": proxies})


@app.route("/api/rules", methods=["GET"])
def get_rules():
    config = load_config()
    path = config.get("routing_file", "")
    if not path:
        return jsonify({"error": "Путь к файлу не задан"}), 400
    if not os.path.exists(path):
        return jsonify({"error": f"Файл не найден: {path}"}), 404
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    editable, _ = get_editable_section(content)
    rules = parse_rules(editable)
    return jsonify({"rules": rules})


@app.route("/api/rules", methods=["POST"])
def add_rule():
    config = load_config()
    path = config.get("routing_file", "")
    if not path:
        return jsonify({"error": "Путь к файлу не задан"}), 400
    if not os.path.exists(path):
        return jsonify({"error": f"Файл не найден: {path}"}), 404

    data = request.get_json()
    domain = data.get("domain", "").strip().lower()
    rule_type = data.get("type", "")
    proxy_address = data.get("proxy_address", "")

    if not domain:
        return jsonify({"error": "Домен не может быть пустым"}), 400
    if not re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', domain):
        return jsonify({"error": "Невалидный домен"}), 400
    if rule_type not in ("DIRECT", "PROXY"):
        return jsonify({"error": "Неверный тип"}), 400
    if rule_type == "PROXY" and not proxy_address:
        return jsonify({"error": "Не выбран прокси-сервер"}), 400

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    editable, protected = get_editable_section(content)
    existing = get_existing_domains(editable)
    if domain in existing or f"*.{domain}" in existing:
        return jsonify({"error": f"Домен уже есть в файле: {domain}"}), 409

    if rule_type == "PROXY":
        editable = insert_proxy_rule(editable, domain, proxy_address)
    else:
        editable = insert_direct_rule(editable, domain)

    with open(path, "w", encoding="utf-8") as f:
        f.write(editable + protected)

    rules = parse_rules(editable)
    return jsonify({"ok": True, "message": f"{domain} → {rule_type} добавлен", "rules": rules})


@app.route("/api/rules/delete", methods=["POST"])
def delete_rule():
    config = load_config()
    path = config.get("routing_file", "")
    if not path:
        return jsonify({"error": "Путь к файлу не задан"}), 400
    if not os.path.exists(path):
        return jsonify({"error": f"Файл не найден: {path}"}), 404

    data = request.get_json()
    rule_type = data.get("type", "")
    domain = data.get("domain", "").strip().lower()
    pattern_str = data.get("pattern", "").strip()

    if rule_type not in ("DIRECT", "PROXY"):
        return jsonify({"error": "Нужен type"}), 400
    if rule_type == "PROXY" and not domain:
        return jsonify({"error": "Нужен domain"}), 400
    if rule_type == "DIRECT" and not pattern_str:
        return jsonify({"error": "Нужен pattern"}), 400

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    editable, protected = get_editable_section(content)

    if rule_type == "PROXY":
        editable_new, removed = _remove_rule(
            editable, lambda r: r["type"] == "PROXY" and r["domain"] == domain
        )
        label = domain
    else:
        editable_new, removed = _remove_rule(
            editable, lambda r: r["type"] == "DIRECT" and r["domain"] == pattern_str
        )
        label = pattern_str

    if not removed:
        return jsonify({"error": f"Правило не найдено: {label}"}), 404

    with open(path, "w", encoding="utf-8") as f:
        f.write(editable_new + protected)

    rules = parse_rules(editable_new)
    return jsonify({"ok": True, "message": f"{label} удалён", "rules": rules})


def _cli():
    """Управление пользователями: adduser / deluser / listusers."""
    cmd = sys.argv[1]
    users = load_users()
    if cmd == "adduser":
        import getpass
        name = sys.argv[2] if len(sys.argv) > 2 else input("Логин: ").strip()
        pw = getpass.getpass("Пароль: ")
        pw2 = getpass.getpass("Повторите пароль: ")
        if not name or not pw:
            print("Логин и пароль не могут быть пустыми"); sys.exit(1)
        if pw != pw2:
            print("Пароли не совпадают"); sys.exit(1)
        users[name] = generate_password_hash(pw)
        save_users(users)
        print(f"Пользователь '{name}' сохранён в {USERS_FILE}")
    elif cmd == "deluser":
        name = sys.argv[2] if len(sys.argv) > 2 else input("Логин: ").strip()
        if users.pop(name, None) is None:
            print(f"Пользователь '{name}' не найден"); sys.exit(1)
        save_users(users)
        print(f"Пользователь '{name}' удалён")
    elif cmd == "listusers":
        print("\n".join(users) if users else "Пользователей нет")
    else:
        print(f"Неизвестная команда: {cmd}")
        print("Доступно: adduser [логин], deluser [логин], listusers")
        sys.exit(1)


def _bootstrap_admin():
    """Создаёт первого пользователя из env, если хранилище пустое (для Docker)."""
    if load_users():
        return
    name = os.environ.get("INITIAL_ADMIN")
    pw = os.environ.get("INITIAL_ADMIN_PASSWORD")
    if name and pw:
        save_users({name: generate_password_hash(pw)})
        print(f"Создан первый пользователь '{name}' из INITIAL_ADMIN")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        _cli()
    else:
        _bootstrap_admin()
        if not load_users():
            print("ВНИМАНИЕ: нет ни одного пользователя — вход невозможен.")
            print("Создайте: python server.py adduser <логин>")
        print("Routing editor запущен: http://localhost:5000")
        app.run(debug=False, port=5000, host='0.0.0.0')
