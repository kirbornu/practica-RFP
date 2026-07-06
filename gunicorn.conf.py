"""Конфигурация gunicorn для прод-запуска Flask-приложения.

Запуск: gunicorn -c gunicorn.conf.py server:app
"""
import os

# Слушаем внутри docker-сети; наружу трафик выпускает Caddy, а не gunicorn.
bind = "0.0.0.0:5000"

# Число воркеров/потоков. Приложение почти всё время ждёт файловый/сетевой
# ввод-вывод, поэтому потоки дешевле процессов.
workers = int(os.environ.get("GUNICORN_WORKERS", "3"))
threads = int(os.environ.get("GUNICORN_THREADS", "4"))

# Логи в stdout/stderr — их подхватывает docker.
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("GUNICORN_LOGLEVEL", "info")

# Caddy стоит на том же docker-хосте, доверяем его заголовкам X-Forwarded-*.
forwarded_allow_ips = "*"

# Перезапускаем воркеры после N запросов — страховка от утечек памяти.
max_requests = 1000
max_requests_jitter = 50


def on_starting(server):
    """Создаём первого пользователя из env один раз, в мастер-процессе,
    до форка воркеров — чтобы не было гонки записи в users.json."""
    import server as app_module
    app_module._bootstrap_admin()
