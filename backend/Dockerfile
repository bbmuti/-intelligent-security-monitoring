FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN groupadd --system sentinel && useradd --system --gid sentinel --home-dir /app sentinel
COPY --chown=sentinel:sentinel app ./app
COPY --chown=sentinel:sentinel migrations ./migrations
COPY --chown=sentinel:sentinel alembic.ini .
USER sentinel
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'"]
