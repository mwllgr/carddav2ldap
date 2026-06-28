FROM python:3.13-alpine

WORKDIR /app

COPY pyproject.toml VERSION.txt ./
COPY src/ src/

RUN apk add --no-cache su-exec && pip install --no-cache-dir ".[http3]"

ENV PUID=1006

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 389 636

ENTRYPOINT ["/docker-entrypoint.sh"]
