FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app
RUN addgroup --system sam && adduser --system --ingroup sam sam
COPY pyproject.toml uv.lock /app/
RUN pip install --no-cache-dir uv==0.13.9 \
    && uv sync --locked --no-dev --no-install-project
COPY backend /app/backend
COPY alembic.ini /app/alembic.ini
RUN mkdir -p /app/uploads && chown -R sam:sam /app
USER sam
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
