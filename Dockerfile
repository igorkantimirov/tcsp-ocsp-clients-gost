# OpenSSL 3 + engine gost + FastAPI (server.py).
# Запуск API: docker run -d -p 8080:8080 -v .../data:/data --name mini-pki-gost-env IMAGE
# Инициализация УЦ в томе: docker exec mini-pki-gost-env sh /app/docker-init-ca.sh
# Только shell + openssl: переопределить CMD, например: docker run ... IMAGE sleep infinity
FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        # build OpenSSL from source (patched ts module)
        build-essential \
        perl \
        wget \
        ca-certificates \
        libengine-gost-openssl \
        python3 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

ARG OPENSSL_VER=3.0.13
WORKDIR /tmp
COPY patches/openssl-3.0.13-ts-ess-issuerSerial.patch /tmp/openssl-ts.patch
RUN wget -q "https://www.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz" \
    && tar -xzf "openssl-${OPENSSL_VER}.tar.gz" \
    && cd "openssl-${OPENSSL_VER}" \
    && patch -p1 < /tmp/openssl-ts.patch \
    && ./Configure linux-x86_64 --prefix=/usr/local --openssldir=/usr/local/ssl shared \
    && make -j"$(nproc)" \
    && make install_sw \
    && echo "/usr/local/lib64" > /etc/ld.so.conf.d/openssl-local.conf \
    && ldconfig \
    && ln -sf /usr/local/bin/openssl /usr/bin/openssl

ENV OPENSSL_ENGINES=/usr/lib/x86_64-linux-gnu/engines-3

COPY openssl-gost.cnf /etc/ssl/openssl-gost.cnf
ENV OPENSSL_CONF=/etc/ssl/openssl-gost.cnf

WORKDIR /app
COPY requirements-docker.txt server.py docker-init-ca.sh docker-smoke.sh ./
RUN pip3 install --break-system-packages --no-cache-dir -r requirements-docker.txt \
    && chmod +x docker-init-ca.sh docker-smoke.sh

VOLUME ["/data"]

EXPOSE 8080
ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080"]
