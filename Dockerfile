# Stage 1 — build wheel
FROM python:3.11-slim-bookworm AS builder
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY apihunter/ apihunter/
RUN pip install --no-cache-dir build && python -m build --wheel

# Stage 2 — runtime
FROM python:3.11-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
LABEL org.opencontainers.image.source="https://github.com/bess1lie/apihunter"
LABEL org.opencontainers.image.description="apihunter — REST API security testing CLI"
LABEL org.opencontainers.image.licenses="MIT"
WORKDIR /app
RUN useradd -m apihunter
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
USER apihunter
ENTRYPOINT ["apihunter"]
CMD ["--help"]
