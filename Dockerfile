FROM python:3.11-slim

WORKDIR /app

RUN pip install flask

COPY server.py .
COPY index.html .

EXPOSE 5000

CMD [ "python", "server.py" ]