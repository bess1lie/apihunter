# Stage 1 — build wheel
FROM python:3.11-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY apihunter/ apihunter/
RUN pip install --no-cache-dir build && python -m build --wheel

# Stage 2 — runtime
FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
ENTRYPOINT ["apihunter"]
CMD ["--help"]
