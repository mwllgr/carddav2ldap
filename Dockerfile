FROM python:3.13-alpine

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir .

EXPOSE 389 636

ENTRYPOINT ["carddav-to-ldap"]
