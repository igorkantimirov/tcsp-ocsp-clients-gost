#!/bin/sh
# Один раз внутри контейнера: создать демо-УЦ, OCSP-подписанта (= CA), TSA с EKU timeStamping.
# Запуск: docker exec mini-pki-gost-env sh /app/docker-init-ca.sh
set -eu
cd /data

if [ -f ca.cert.pem ] && [ "${FORCE:-0}" != 1 ]; then
  echo "Уже есть /data/ca.cert.pem (FORCE=1 для пересоздания)" >&2
  exit 0
fi

# Для совместимости (как в real-cert-root.cer): publicKeyParamSet=CryptoPro-A (1.2.643.2.2.35.1)
openssl genpkey -engine gost -algorithm gost2012_256 -pkeyopt paramset:1.2.643.2.2.35.1 -out ca.key.pem
# Root должен быть X.509 v3 CA (иначе JCSP может не строить цепочку)
printf '%s\n' \
  'basicConstraints=critical,CA:TRUE,pathlen:0' \
  'keyUsage=critical,keyCertSign,cRLSign' \
  'subjectKeyIdentifier=hash' \
  'authorityKeyIdentifier=keyid:always,issuer' > ca.ext.cnf
openssl req -new -key ca.key.pem -engine gost -subj "/CN=DEMO GOST CA" -out ca.csr.pem
openssl x509 -req -in ca.csr.pem -signkey ca.key.pem -engine gost -days 3650 \
  -extfile ca.ext.cnf -out ca.cert.pem

# Минимальный openssl ca config для генерации CRL из /data/index.txt
cat > /data/openssl-ca.cnf <<'ENDCFG'
[ ca ]
default_ca = CA_default

[ CA_default ]
database = /data/index.txt
new_certs_dir = /data/newcerts
certificate = /data/ca.cert.pem
private_key = /data/ca.key.pem
serial = /data/ca.srl
crlnumber = /data/crlnumber
default_md = md_gost12_256
default_crl_days = 7
crl_extensions = crl_ext
unique_subject = no

[ crl_ext ]
authorityKeyIdentifier = keyid:always
ENDCFG

mkdir -p /data/newcerts
: > /data/index.txt
echo 01 > /data/ca.srl
echo 01 > /data/crlnumber

# OCSP подписывает тем же ключом (демо)
# Важно для CryptoPro/AdES: OCSP должен быть подписан OCSP-responder сертификатом с EKU OCSPSigning,
# а не CA-сертификатом.
openssl genpkey -engine gost -algorithm gost2012_256 -pkeyopt paramset:1.2.643.2.2.35.1 -out ocsp.key.pem
printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'extendedKeyUsage=critical,OCSPSigning' \
  'keyUsage=critical,digitalSignature' \
  'subjectKeyIdentifier=hash' \
  'authorityKeyIdentifier=keyid:always,issuer' \
  'noCheck=critical' > ocsp.ext.cnf
openssl req -new -key ocsp.key.pem -engine gost -subj "/CN=DEMO OCSP Responder" -out ocsp.csr.pem
openssl x509 -req -in ocsp.csr.pem -CA ca.cert.pem -CAkey ca.key.pem -engine gost -days 3650 \
  -CAserial ca.srl -extfile ocsp.ext.cnf -out ocsp.cert.pem

openssl genpkey -engine gost -algorithm gost2012_256 -pkeyopt paramset:1.2.643.2.2.35.1 -out tsa.key.pem
cat > /data/tsa.ext.cnf <<'ENDCFG'
[tsa_ext]
basicConstraints = critical,CA:FALSE
extendedKeyUsage = critical,timeStamping
keyUsage = critical,digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
crlDistributionPoints = URI:http://host.docker.internal:8080/crl.crl
authorityInfoAccess = OCSP;URI:http://host.docker.internal:8080/ocsp,caIssuers;URI:http://host.docker.internal:8080/ca.cer
ENDCFG
openssl req -new -key tsa.key.pem -engine gost -subj "/CN=DEMO TSA" -out tsa.csr.pem \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'extendedKeyUsage=critical,timeStamping' \
  -addext 'keyUsage=critical,digitalSignature' \
  -addext 'subjectKeyIdentifier=hash' \
  -addext 'crlDistributionPoints=URI:http://host.docker.internal:8080/crl.crl' \
  -addext 'authorityInfoAccess=OCSP;URI:http://host.docker.internal:8080/ocsp,caIssuers;URI:http://host.docker.internal:8080/ca.cer'
# TSA сертификат должен быть выдан CA (иначе цепочка не строится в JCSP)
openssl x509 -req -in tsa.csr.pem -CA ca.cert.pem -CAkey ca.key.pem -engine gost -days 3650 \
  -CAserial ca.srl -copy_extensions copyall -out tsa.cert.pem

# Файл цепочки для TSP-ответов (чтобы клиенты могли построить цепочку без внешнего хранилища)
cat /data/tsa.cert.pem /data/ca.cert.pem > /data/tsa.chain.pem

# OCSP (openssl ocsp -index) отвечает только по index.txt.
# Добавляем TSA-серт как "Valid", иначе JCSP/JCPRevCheck будет получать статус unknown
# и валидатор упадёт с "Could not determine revocation status".
python3 - <<'PY'
import email.utils
import re
from datetime import timezone
from pathlib import Path

def run(cmd):
    import subprocess
    p = subprocess.run(cmd, capture_output=True, check=False)
    if p.returncode != 0:
        raise SystemExit(p.stderr.decode("utf-8", "replace")[:2000] or "command failed")
    return p.stdout.decode("utf-8", "replace")

out = run([
    "openssl","x509","-in","/data/tsa.cert.pem","-noout",
    "-serial","-enddate","-subject","-nameopt","esc_2253,utf8,-esc_msb"
])
serial_m = re.search(r"^serial=(.+)$", out, re.M)
end_m = re.search(r"^notAfter=(.+)$", out, re.M)
subj_m = re.search(r"^subject=(.+)$", out, re.M)
if not serial_m or not end_m or not subj_m:
    raise SystemExit("failed to parse openssl x509 output")

serial = serial_m.group(1).strip().upper().replace(":", "")
not_after = end_m.group(1).strip()
subject = subj_m.group(1).strip()
dt = email.utils.parsedate_to_datetime(not_after)
if dt.tzinfo is None:
    dt = dt.replace(tzinfo=timezone.utc)
dt = dt.astimezone(timezone.utc)
exp = dt.strftime("%y%m%d%H%M%SZ")
if not subject.startswith("/"):
    subject = "/" + subject.replace(", ", "/").replace(",", "/")

line = f"V\t{exp}\t\t{serial}\tunknown\t{subject}\n"
Path("/data/index.txt").write_text(Path("/data/index.txt").read_text(encoding="utf-8") + line, encoding="utf-8")
PY

mkdir -p /data/tsa
echo 01 > /data/tsa/tsaserial

cat > /data/tsa/openssl-tsa.cnf << 'ENDCFG'
openssl_conf = openssl_init
[openssl_init]
engines = engine_section
[engine_section]
gost = gost_section
[gost_section]
default_algorithms = ALL

[ tsa ]
default_tsa = tsa1

[ tsa1 ]
dir = /data/tsa
serial = /data/tsa/tsaserial
signer_cert = /data/tsa.cert.pem
signer_key = /data/tsa.key.pem
certs = /data/ca.cert.pem
signer_digest = md_gost12_256
default_policy = 1.2.3.4.5.6.7.8.9
digests = md_gost12_256
ess_cert_id_alg = md_gost12_256
accuracy = secs:1,millisecs:0,microsecs:0
ordering = yes
ess_cert_id_chain = yes
crypto_device = builtin
other_policies = 1.2.3.4.5.6.7.8.10

[ tsa_policy1 ]
oid = 1.2.3.4.5.6.7.8.9
ENDCFG

echo "Готово: ca.cert.pem, ca.key.pem, ocsp.*, tsa.*, index.txt, /data/tsa/openssl-tsa.cnf"
