FROM python:3.12-slim AS builder

WORKDIR /build

COPY --from=ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./
RUN uv export --frozen --extra sourcehunt --no-dev --no-emit-project -o requirements.txt \
 && uv pip install --system --no-cache --exact -r requirements.txt

COPY . .
RUN uv pip install --system --no-cache --no-deps .

# -------------------------------------------------------------------
FROM python:3.12-slim

WORKDIR /app

RUN adduser --system --no-create-home clearwing

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

USER clearwing

ENTRYPOINT ["clearwing"]
