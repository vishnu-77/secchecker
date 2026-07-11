# demo/Dockerfile — Intentionally misconfigured for secchecker demonstration.
# DO NOT use this in production.

# [HIGH] Unpinned base image — FROM python:latest makes builds non-reproducible
# and may pull an image with known CVEs on the next build
FROM python:latest

WORKDIR /app

# [HIGH] Secret in ENV — credentials baked into the image layer, visible in
# docker inspect and image registries
ENV DATABASE_URL="postgresql://admin:hunter2@db.internal:5432/prod"

COPY requirements.txt .

# [HIGH] curl-pipe-bash — downloads and executes an unverified script
RUN curl -sSL https://get.setup-helper.io | bash

RUN pip install -r requirements.txt

COPY . .

# [MEDIUM] Running as root — any container escape gives the attacker root on the host
# Add: USER nonroot
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
