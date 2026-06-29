FROM python:3.11-slim

WORKDIR /app

RUN pip install flask

COPY server.py .
COPY *.html .

EXPOSE 5000

CMD [ "python", "server.py" ]