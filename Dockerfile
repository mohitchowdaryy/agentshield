# Backend API, with Checkov for IaC scanning (the dashboard has its own image).
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN useradd --create-home --uid 10001 agentshield
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install ".[anthropic]"
# Checkov in its own virtualenv so its dependencies cannot change AgentShield's pinned versions.
RUN python -m venv /opt/checkov && /opt/checkov/bin/pip install checkov==3.3.29
COPY terraform-lab ./terraform-lab
USER agentshield
ENV AGENTSHIELD_DATABASE_URL=sqlite:////home/agentshield/data/agentshield.db \
    AGENTSHIELD_STATIC_DIR=/nonexistent \
    AGENTSHIELD_CHECKOV_PATH=/opt/checkov/bin/checkov \
    AGENTSHIELD_IAC_LAB_DIR=/app/terraform-lab
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"
# 0.0.0.0 inside the container only; docker-compose publishes it on 127.0.0.1.
CMD ["agentshield", "serve", "--host", "0.0.0.0", "--port", "8000"]
