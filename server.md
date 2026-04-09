# Server (demo PKI: CA + OCSP + TSA)

## Сборка образа

```bash
docker build -t mini-pki-gost:latest .
```

## Запуск

```bash
docker rm -f mini-pki-gost
docker run -d --name mini-pki-gost -p 8080:8080 -v "${PWD}/data:/data" mini-pki-gost:latest
```

## Инициализация CA/OCSP/TSA в томе `/data`

```bash
docker exec mini-pki-gost sh -lc "/app/docker-init-ca.sh"
```
