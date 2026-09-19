FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md constraints.txt ./
COPY src ./src

RUN pip install --upgrade pip && pip install . -c constraints.txt

# Loopback-only sidecar; run unprivileged.
RUN useradd --system --uid 10001 adds && chown -R adds /app
USER adds

EXPOSE 8080

CMD ["adds-mcp"]
