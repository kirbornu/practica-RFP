FROM python:3.11-slim

WORKDIR /app

# Ставим зависимости отдельным слоем — кешируется, пока requirements не менялся.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py gunicorn.conf.py ./
COPY *.html ./

EXPOSE 5000 5001

# Прод-запуск через gunicorn (не через встроенный dev-сервер Flask).
CMD ["gunicorn", "-c", "gunicorn.conf.py", "server:app"]
