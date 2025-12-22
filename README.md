# TSP и OCSP клиенты на Python с поддержкой ГОСТ

Клиенты для запросов к **TSP** (RFC 3161) и **OCSP** с использованием **ГОСТ Р 34.11-2012** для хешей в протоколе.

## Установка

```bash
pip install -r requirements.txt
```

## OCSP-клиент

В запросе **CertID** поля `issuerNameHash` и `issuerKeyHash` считаются по **ГОСТ Р 34.11-2012** (256 или 512 бит), как принято в российской криптографии.

CLI:

```bash
python -m TSPOCSPCLIENT ocsp http://ocsp.example.com/ocsp.srf user.pem ca.pem
```

## TSP-клиент

В **TimeStampReq** поле **MessageImprint** формируется с алгоритмом **ГОСТ Р 34.11-2012** и хешем данных.

```python
from TSPOCSPCLIENT import TSPClient

client = TSPClient("http://tsa.example.com/tsp/tsp.srf")
result = client.timestamp(b"payload", digest_size=256)
print(result.status)  # granted, rejection, ...
if result.tst_info:
    print(result.tst_info["gen_time"].native)
    assert client.verify_imprint(b"payload", result, 256)
```

CLI:

```bash
python -m TSPOCSPCLIENT tsp http://tsa.example.com/tsp/tsp.srf document.pdf
```

Сохраняет цепочку в `./output`

## Ограничения

- **Подпись OCSP-ответа** и **подпись TimeStampToken (CMS)** по ГОСТ не проверяются в этом пакете; для полной криптографической проверки используйте КриптоПро CSP или расширение с поддержкой ГОСТ CMS.


## Пример TSP

`http://pki.tax.gov.ru/tsp/tsp.srf`

`http://tax4.tensor.ru/tsp/tsp.srf`

