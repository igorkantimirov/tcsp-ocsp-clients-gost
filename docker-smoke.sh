#!/bin/sh
set -eu
i=0
while ! python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)" 2>/dev/null; do
  i=$((i + 1))
  if [ "$i" -gt 30 ]; then echo "API не поднялся"; exit 1; fi
  sleep 0.5
done
sleep 1
openssl genpkey -engine gost -algorithm gost2012_256 -pkeyopt paramset:1.2.643.2.2.35.1 -out /data/client.key.pem
openssl req -new -key /data/client.key.pem -engine gost -subj "/CN=API" -out /data/client.csr
python3 -c "
import base64, urllib.request
der = open('/data/client.csr', 'rb').read()
# CSR сейчас PEM; конвертим в DER через openssl (в контейнере).
import subprocess, os, tempfile
with tempfile.NamedTemporaryFile(delete=False) as f:
    f.write(der); name=f.name
p = subprocess.run(['openssl','req','-inform','PEM','-in',name,'-outform','DER'], capture_output=True)
os.unlink(name)
csr_der = p.stdout
csr_b64 = base64.b64encode(csr_der).decode()
boundary = '----X'
body = (
    f'--{boundary}\\r\\n'
    'Content-Disposition: form-data; name=\"csr_b64\"\\r\\n\\r\\n'
    + csr_b64 + '\\r\\n'
    f'--{boundary}--\\r\\n'
).encode()
req = urllib.request.Request('http://127.0.0.1:8080/sign-csr', data=body, method='POST',
    headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})
open('/data/api-cert.cer','wb').write(urllib.request.urlopen(req).read())
"
# Для OCSP нужен leaf cert в PEM — конвертим из ответа API (.cer DER)
openssl x509 -inform DER -in /data/api-cert.cer -outform PEM -out /data/api-cert.pem
openssl ocsp -issuer /data/ca.cert.pem -cert /data/api-cert.pem -reqout /data/ocspreq.der
python3 -c "
import urllib.request
b = open('/data/ocspreq.der', 'rb').read()
req = urllib.request.Request('http://127.0.0.1:8080/ocsp', data=b, method='POST',
    headers={'Content-Type': 'application/ocsp-request'})
open('/data/ocspresp.der', 'wb').write(urllib.request.urlopen(req).read())
"
echo hi > /data/hi.txt
openssl ts -query -data /data/hi.txt -md_gost12_256 -cert -out /data/q.tsq
python3 -c "
import urllib.request
b = open('/data/q.tsq', 'rb').read()
req = urllib.request.Request('http://127.0.0.1:8080/tsp', data=b, method='POST',
    headers={'Content-Type': 'application/timestamp-query'})
open('/data/r.tsr', 'wb').write(urllib.request.urlopen(req).read())
"

# CRL должен отдаваться и парситься
python3 -c "
import urllib.request
open('/data/ca.crl', 'wb').write(urllib.request.urlopen('http://127.0.0.1:8080/crl.crl').read())
"
openssl crl -inform DER -in /data/ca.crl -noout -text >/dev/null
echo OK: api-cert ocspresp r.tsr
