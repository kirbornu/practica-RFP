import pytest
import server


# --- Разбор PROXY-правил -----------------------------------------------------

def test_parse_single_proxy_rule():
    """parse_rules() должен вытащить из текста один PROXY и разобрать его на части."""
    # 1. ПОДГОТОВКА (arrange): исходные данные — кусок PAC-файла.
    content = 'if (shExpMatch(host, "example.com")) { return "PROXY 1.2.3.4:3128"; }'

    # 2. ДЕЙСТВИЕ (act): вызываем тестируемую функцию.
    rules = server.parse_rules(content)

    # 3. ПРОВЕРКА (assert): результат должен быть ровно таким.
    assert rules == [
        {"domain": "example.com", "type": "PROXY", "proxy": "1.2.3.4:3128"}
    ]


def test_parse_ignores_wildcard_branch():
    """У PROXY-правила две ветки: "domain" и "*.domain". Парсер должен взять
    чистый домен, а не звёздочный вариант — иначе в UI появился бы "*.example.com"."""
    content = (
        'if (shExpMatch(host, "example.com") || shExpMatch(host, "*.example.com")) {\n'
        '    return "PROXY 1.2.3.4:3128";\n'
        '}'
    )
    rules = server.parse_rules(content)
    assert len(rules) == 1
    assert rules[0]["domain"] == "example.com"  # без "*."


# --- Разбор DIRECT-правил ----------------------------------------------------

def test_parse_direct_rule():
    """DIRECT-правило хранит полный шаблон целиком (со звёздочками)."""
    content = 'if (shExpMatch(url, "*//example.ru/*")) {return "DIRECT";}'
    rules = server.parse_rules(content)
    assert rules == [
        {"domain": "*//example.ru/*", "type": "DIRECT", "proxy": None}
    ]


# --- Несколько правил в одном файле -----------------------------------------

def test_parse_multiple_rules_in_order():
    """Парсер должен вернуть все правила в порядке их появления в тексте."""
    content = (
        'if (shExpMatch(host, "a.com")) { return "PROXY 1.1.1.1:3128"; }\n'
        'if (shExpMatch(host, "b.com")) { return "PROXY 2.2.2.2:8080"; }\n'
        'if (shExpMatch(url, "*//c.ru/*")) {return "DIRECT";}'
    )
    rules = server.parse_rules(content)
    domains = [r["domain"] for r in rules]
    assert domains == ["a.com", "b.com", "*//c.ru/*"]

@pytest.mark.parametrize("pac_text, expected_domain, expected_type", [
    # обычный PROXY
    ('if (shExpMatch(host, "a.com")) { return "PROXY 1.1.1.1:3128"; }', "a.com", "PROXY"),
    # PROXY с портом-нестандартом
    ('if (shExpMatch(host, "b.io")) { return "PROXY 2.2.2.2:10808"; }', "b.io", "PROXY"),
    # DIRECT со звёздочным шаблоном
    ('if (shExpMatch(url, "*//c.ru/*")) {return "DIRECT";}', "*//c.ru/*", "DIRECT"),
    # домен с дефисом и поддоменом
    ('if (shExpMatch(host, "my-site.co.uk")) { return "PROXY 3.3.3.3:80"; }', "my-site.co.uk", "PROXY"),
])
def test_parse_various_rules(pac_text, expected_domain, expected_type):
    rules = server.parse_rules(pac_text)
    assert len(rules) == 1
    assert rules[0]["domain"] == expected_domain
    assert rules[0]["type"] == expected_type


def test_parse_ignores_non_rule_ifs():
    content = 'if (isInNet(host, "10.0.0.0", "255.0.0.0")) {return "DIRECT";}'
    content2 = 'if (host == "x") { doSomething(); }'
    assert server.parse_rules(content2) == []


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


def test_roundtrip_insert_then_parse_proxy():
    """Вставленное PROXY-правило должно быть видно парсеру со всеми полями."""
    content = server.insert_proxy_rule(PAC_TEMPLATE, "example.com", "9.9.9.9:3128")
    editable, _ = server.get_editable_section(content)
    rules = server.parse_rules(editable)
    assert {"domain": "example.com", "type": "PROXY", "proxy": "9.9.9.9:3128"} in rules


def test_roundtrip_insert_then_remove():
    """Вставили два правила, удалили одно — остаётся ровно второе."""
    content = server.insert_proxy_rule(PAC_TEMPLATE, "a.com", "1.1.1.1:3128")
    content = server.insert_proxy_rule(content, "b.com", "2.2.2.2:3128")

    # _remove_rule принимает предикат: какое правило удалять.
    content, removed = server._remove_rule(
        content, lambda r: r["type"] == "PROXY" and r["domain"] == "a.com"
    )
    assert removed is True

    editable, _ = server.get_editable_section(content)
    domains = [r["domain"] for r in server.parse_rules(editable)]
    assert "a.com" not in domains
    assert "b.com" in domains


def test_remove_returns_false_when_not_found():
    """Если правила нет — _remove_rule возвращает removed=False и не портит текст."""
    content, removed = server._remove_rule(
        PAC_TEMPLATE, lambda r: r["domain"] == "does-not-exist.com"
    )
    assert removed is False
    assert content == PAC_TEMPLATE  # текст не изменился
    

def test_constants_section_is_protected():
    editable, protected = server.get_editable_section(PAC_TEMPLATE)
    # localhost описан в секции констант -> он в protected, а не в editable.
    assert "localhost" not in editable
    assert "localhost" in protected
    # А объединение двух частей даёт исходный файл без потерь.
    assert editable + protected == PAC_TEMPLATE


def test_existing_domains_detects_duplicates():
    """get_existing_domains нужен, чтобы не добавить дубль. Проверяем, что он
    находит уже присутствующий домен."""
    content = server.insert_proxy_rule(PAC_TEMPLATE, "dup.com", "1.1.1.1:3128")
    assert "dup.com" in server.get_existing_domains(content)
