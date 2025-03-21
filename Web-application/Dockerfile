FROM python:3.13-slim AS builder

WORKDIR /flask_app

COPY . .

RUN apt-get update && apt-get install -y gcc libpq-dev && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-alpine AS runtime

WORKDIR /flask_app

RUN apk add --no-cache libpq

COPY --from=builder /install /usr/local

COPY . .

EXPOSE 8000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "flask_app:create_app()"]
