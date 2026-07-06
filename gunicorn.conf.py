"""Конфигурация gunicorn для прод-запуска Flask-приложения.

Запуск: gunicorn -c gunicorn.conf.py server:app
"""
import os

# Слушаем два порта в одном процессе:
#   5000 — приватный: авторизация + редактор + тетрис;
#   5001 — публичный: без авторизации, только тетрис (см. PUBLIC_PORTS в server.py).
# Приложение различает их по реальному порту сокета (SERVER_PORT), а не по Host.
bind = ["0.0.0.0:5000", "0.0.0.0:5001"]

# Число воркеров/потоков. Приложение почти всё время ждёт файловый/сетевой
# ввод-вывод, поэтому потоки дешевле процессов.
workers = int(os.environ.get("GUNICORN_WORKERS", "3"))
threads = int(os.environ.get("GUNICORN_THREADS", "4"))

# Логи в stdout/stderr — их подхватывает docker.
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("GUNICORN_LOGLEVEL", "info")

# Перезапускаем воркеры после N запросов — страховка от утечек памяти.
max_requests = 1000
max_requests_jitter = 50


def on_starting(server):
    """Создаём первого пользователя из env один раз, в мастер-процессе,
    до форка воркеров — чтобы не было гонки записи в users.json."""
    import server as app_module
    app_module._bootstrap_admin()
