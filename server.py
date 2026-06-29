import json
import os
import re
import secrets
import sys
from flask import (
    Flask, request, jsonify, send_from_directory,
    session, redirect, url_for,
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

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

# Эндпоинты, доступные без входа.
PUBLIC_ENDPOINTS = {"login_page", "login", "static"}


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
def require_login():
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
    pw_hash = load_users().get(username)
    if not pw_hash or not check_password_hash(pw_hash, password):
        return jsonify({"error": "Неверный логин или пароль"}), 401
    session["user"] = username
    return jsonify({"ok": True, "user": username})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/api/me", methods=["GET"])
def whoami():
    return jsonify({"user": session.get("user")})


@app.route("/")
def home():
    return send_from_directory(BASE_DIR, "home.html")


@app.route("/editor")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/tetris")
def tetris():
    return send_from_directory(BASE_DIR, "tetris.html")


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
