FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install --yes --no-install-recommends dnsutils whois ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 nexus
RUN mkdir -p /home/nexus/.osint-toolkit/tools /home/nexus/.osint-toolkit/output \
    && chown -R nexus:nexus /home/nexus/.osint-toolkit
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY osint_toolkit ./osint_toolkit
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir ".[web]"

USER nexus
EXPOSE 8000

CMD ["uvicorn", "osint_toolkit.api:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
