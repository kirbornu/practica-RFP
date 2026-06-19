import json
import os
import re
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")


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


def parse_rules(content):
    """Парсит правила shExpMatch из редактируемой части файла."""
    rules = []
    # PROXY: if (shExpMatch(host, "domain") || ...) { return "PROXY ..."; }
    for m in re.finditer(
        r'if\s*\(shExpMatch\(host,\s*["\']([^"\'*][^"\']*)["\'][^)]*\)\s*(?:\|\|[^)]*\))?\s*\)\s*\{[^}]*return\s*["\']PROXY\s+([\w\.\-]+:\d+)["\'];',
        content
    ):
        rules.append({"domain": m.group(1), "type": "PROXY", "proxy": m.group(2)})

    # DIRECT: захватываем весь паттерн целиком (url или host)
    for m in re.finditer(
        r'if\s*\(shExpMatch\((?:url|host),\s*["\']([^"\']+)["\']\s*\)\s*\)\s*\{return\s*["\']DIRECT["\'];',
        content
    ):
        rules.append({"domain": m.group(1), "type": "DIRECT", "proxy": None})

    return rules


def delete_proxy_rule(content, domain):
    """Удаляет многострочный if-блок для PROXY по host."""
    pattern = (
        r'\n[ \t]*if\s*\(shExpMatch\(host,\s*["\']' + re.escape(domain) + r'["\']'
        r'[^)]*\)\s*(?:\|\|[^)]*\))?\s*\)\s*\{[^}]*\}'
    )
    return re.sub(pattern, '', content)


def delete_direct_rule(content, pattern_str):
    """Удаляет однострочный if для DIRECT по полному паттерну."""
    pattern = (
        r'\n[ \t]*if\s*\(shExpMatch\((?:url|host),\s*["\']'
        + re.escape(pattern_str)
        + r'["\']\s*\)\s*\)\s*\{return\s*["\']DIRECT["\'];[ \t]*\}'
    )
    return re.sub(pattern, '', content)


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
    rule = f'\n\tif (shExpMatch(url, "*//{ domain }/*")) {{return "DIRECT";}}'
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

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


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
        editable_new = delete_proxy_rule(editable, domain)
        label = domain
    else:
        editable_new = delete_direct_rule(editable, pattern_str)
        label = pattern_str

    if editable_new == editable:
        return jsonify({"error": f"Правило не найдено: {label}"}), 404

    with open(path, "w", encoding="utf-8") as f:
        f.write(editable_new + protected)

    rules = parse_rules(editable_new)
    return jsonify({"ok": True, "message": f"{label} удалён", "rules": rules})


if __name__ == "__main__":
    print("Routing editor запущен: http://localhost:5000")
    app.run(debug=False, port=5000, host='0.0.0.0')
