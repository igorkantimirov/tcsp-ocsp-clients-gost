#!/usr/bin/env python
"""
Генерирует CSR через CryptoPro.
Работает под Windows
Требует наличия CryptoPro CSP
Требует pywin32 (`pip install pywin32`)

Предназначен для получения сертификата с произвольными данными.
Можно использовать, например, УЦ https://testgost2012.cryptopro.ru/certsrv/certrqxt.asp

Примеры:
1) Юридическое лицо (ГОСТ 2012):
python generate_csr.py --cn "ООО Ромашка" --o "ООО Ромашка" --c RU --sn "Иванов" --g "Иван" --t "Руководитель" --street "Улица Дубки" --ou "Отдел маркетинга" --email example@example.com --ogrn 1027700132195 --inn-ul 7707083893 --kpp 770701001 --provider-type 80 --out csr_ul.b64 --pem-out csr_ul.pem

2) Физическое лицо:
python generate_csr.py --cn "Иванов Иван Иванович" --sn "Иванов" --g "Иван" --c RU --inn-fl 770123456789 --snils 11223344595 --provider-type 80 --out csr_fl.b64 --pem-out csr_fl.pem
"""

from __future__ import annotations

import argparse
import sys
from typing import Iterable, List, Optional

try:
    import win32com.client
except ImportError as exc:
    print("pywin32 is required: pip install pywin32", file=sys.stderr)
    raise SystemExit(1) from exc


PROVIDER_GOST_2001 = 75
PROVIDER_GOST_2012 = 80

XCN_AT_SIGNATURE = 0x2
XCN_NCRYPT_ALLOW_EXPORT_FLAG = 0x1
CONTEXT_USER = 0x1

XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE = 0x80
XCN_CERT_NON_REPUDIATION_KEY_USAGE = 0x40
XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE = 0x20
XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE = 0x10

XCN_CERT_NAME_STR_ENABLE_PUNYCODE_FLAG = 0x200000
XCN_CRYPT_STRING_BASE64 = 0x1

MAX_CSP_NAME_LEN = 127
ASN1_UTF8STRING_TAG = 0x0C

DEFAULT_EKU_OIDS = [
    "1.3.6.1.5.5.7.3.2",  # clientAuth
    "1.3.6.1.5.5.7.3.4",  # emailProtection
]

SUBJECT_SIGN_TOOL_OID = "1.2.643.100.111"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate CSR (PKCS#10) with CryptoPro CSP")

    parser.add_argument(
        "--subject",
        help='Raw X500 subject string, e.g. CN="Test", OID.1.2.643.100.1="102..."',
    )

    parser.add_argument("--cn", help="Common Name")
    parser.add_argument("--sn", help="Surname (SN)")
    parser.add_argument("--g", help="Given Name (G)")
    parser.add_argument("--t", help="Title (T)")
    parser.add_argument("--street", help="Street (STREET)")
    parser.add_argument("--o", help="Organization")
    parser.add_argument("--ou", help="Org Unit")
    parser.add_argument("--c", help="Country, e.g. RU")
    parser.add_argument("--st", help="State/Province")
    parser.add_argument("--l", help="Locality")
    parser.add_argument("--email", help="Email Address")

    parser.add_argument("--ogrn", help="OID 1.2.643.100.1")
    parser.add_argument("--innle", help="OID 1.2.643.100.4 (INNLE)")
    parser.add_argument("--inn-ul", dest="inn_ul", help="Alias for INNLE, OID 1.2.643.100.4")
    parser.add_argument("--kpp", help="OID 1.2.643.100.6")
    parser.add_argument("--inn", help="OID 1.2.643.3.131.1.1 (INN individual)")
    parser.add_argument("--inn-fl", dest="inn_fl", help="Alias for INN, OID 1.2.643.3.131.1.1")
    parser.add_argument("--snils", help="OID 1.2.643.100.3")
    parser.add_argument("--ogrnip", help="OID 1.2.643.100.5")

    parser.add_argument(
        "--subject-oid",
        action="append",
        default=[],
        metavar="OID=VALUE",
        help='Extra subject OID pair, e.g. --subject-oid 1.2.643.100.7="value"',
    )

    parser.add_argument(
        "--eku",
        action="append",
        default=[],
        help="Extended Key Usage OID, repeatable. Defaults to clientAuth+emailProtection.",
    )
    parser.add_argument(
        "--provider-type",
        type=int,
        choices=[PROVIDER_GOST_2001, PROVIDER_GOST_2012],
        default=PROVIDER_GOST_2012,
        help="CryptoPro provider type: 80 (GOST 2012, default) or 75 (GOST 2001)",
    )
    parser.add_argument("--provider-name", help="Optional explicit CSP name")
    parser.add_argument("--pin", help="Optional key container PIN")
    parser.add_argument("--out", help="Output file for base64 CSR")
    parser.add_argument("--pem-out", help="Optional output file with BEGIN/END CERTIFICATE REQUEST")
    parser.add_argument(
        "--no-subject-sign-tool",
        action="store_true",
        help="Do not add OID 1.2.643.100.111 extension",
    )

    return parser.parse_args()


def quote_dn_value(value: str) -> str:
    return value.replace('"', '""')


def build_subject(args: argparse.Namespace) -> str:
    if args.subject:
        return args.subject.strip()

    parts: List[str] = []

    def add(name: str, val: Optional[str]) -> None:
        if val:
            parts.append(f'{name}="{quote_dn_value(val)}"')

    add("CN", args.cn)
    add("SN", args.sn)
    add("G", args.g)
    add("T", args.t)
    add("STREET", args.street)
    add("O", args.o)
    add("OU", args.ou)
    add("C", args.c)
    add("S", args.st)
    add("L", args.l)
    add("E", args.email)

    add("OID.1.2.643.100.1", args.ogrn)
    inn_ul = args.inn_ul or args.innle
    inn_fl = args.inn_fl or args.inn
    add("OID.1.2.643.100.4", inn_ul)
    add("OID.1.2.643.100.6", args.kpp)
    add("OID.1.2.643.3.131.1.1", inn_fl)
    add("OID.1.2.643.100.3", args.snils)
    add("OID.1.2.643.100.5", args.ogrnip)

    for item in args.subject_oid:
        if "=" not in item:
            raise ValueError(f"Invalid --subject-oid value: {item!r}, expected OID=VALUE")
        oid, value = item.split("=", 1)
        oid = oid.strip()
        value = value.strip().strip('"')
        if not oid:
            raise ValueError(f"Invalid --subject-oid value: {item!r}, empty OID")
        add(f"OID.{oid}", value)

    if not parts:
        raise ValueError("Subject is empty. Provide --subject or at least one DN field (e.g. --cn).")

    return ", ".join(parts)


def chunk_64(text: str) -> str:
    return "\n".join(text[i : i + 64] for i in range(0, len(text), 64))


def to_utf8_der_utf8string_base64(value: str) -> str:
    short_name = value[:MAX_CSP_NAME_LEN]
    utf8_bytes = short_name.encode("utf-8")
    if len(utf8_bytes) <= 127:
        der = bytes([ASN1_UTF8STRING_TAG, len(utf8_bytes)]) + utf8_bytes
    else:
        length_bytes = len(utf8_bytes).to_bytes((len(utf8_bytes).bit_length() + 7) // 8, "big")
        der = bytes([ASN1_UTF8STRING_TAG, 0x80 | len(length_bytes)]) + length_bytes + utf8_bytes

    import base64

    return base64.b64encode(der).decode("ascii")


def resolve_provider_name(provider_type: int) -> str:
    csp_infos = win32com.client.Dispatch("X509Enrollment.CCspInformations")
    csp_infos.AddAvailableCsps()

    count = csp_infos.Count
    for i in range(count):
        item = csp_infos.ItemByIndex(i)
        if bool(item.LegacyCsp) and int(item.Type) == int(provider_type):
            return str(item.Name)
    raise RuntimeError(f"No suitable CSP found for provider type {provider_type}")


def generate_csr(
    subject: str,
    eku_oids: Iterable[str],
    provider_type: int,
    provider_name: Optional[str],
    pin: Optional[str],
    include_subject_sign_tool: bool,
) -> str:
    enroll = win32com.client.Dispatch("X509Enrollment.CX509Enrollment")
    request = win32com.client.Dispatch("X509Enrollment.CX509CertificateRequestPkcs10")
    private_key = win32com.client.Dispatch("X509Enrollment.CX509PrivateKey")
    dn = win32com.client.Dispatch("X509Enrollment.CX500DistinguishedName")

    key_usage = win32com.client.Dispatch("X509Enrollment.CX509ExtensionKeyUsage")
    enhanced_key_usage = win32com.client.Dispatch("X509Enrollment.CX509ExtensionEnhancedKeyUsage")
    enhanced_key_usage_oids = win32com.client.Dispatch("X509Enrollment.CObjectIds")

    csp_name = provider_name or resolve_provider_name(provider_type)

    private_key.KeySpec = XCN_AT_SIGNATURE
    private_key.Existing = False
    private_key.ExportPolicy = XCN_NCRYPT_ALLOW_EXPORT_FLAG
    private_key.ProviderType = provider_type
    private_key.ProviderName = csp_name
    if pin:
        private_key.Pin = pin

    request.InitializeFromPrivateKey(CONTEXT_USER, private_key, "")

    usage_bits = (
        XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE
        | XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE
        | XCN_CERT_NON_REPUDIATION_KEY_USAGE
        | XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE
    )
    key_usage.InitializeEncode(usage_bits)

    for oid_val in eku_oids:
        oid = win32com.client.Dispatch("X509Enrollment.CObjectId")
        oid.InitializeFromValue(str(oid_val))
        enhanced_key_usage_oids.Add(oid)
    enhanced_key_usage.InitializeEncode(enhanced_key_usage_oids)

    request.X509Extensions.Add(key_usage)
    request.X509Extensions.Add(enhanced_key_usage)

    if include_subject_sign_tool:
        ss_oid = win32com.client.Dispatch("X509Enrollment.CObjectId")
        ss_oid.InitializeFromValue(SUBJECT_SIGN_TOOL_OID)
        ss_ext = win32com.client.Dispatch("X509Enrollment.CX509Extension")
        ss_base64 = to_utf8_der_utf8string_base64(csp_name)
        ss_ext.Initialize(ss_oid, XCN_CRYPT_STRING_BASE64, ss_base64)
        request.X509Extensions.Add(ss_ext)

    dn.Encode(subject, XCN_CERT_NAME_STR_ENABLE_PUNYCODE_FLAG)
    request.Subject = dn

    enroll.InitializeFromRequest(request)
    return str(enroll.CreateRequest(XCN_CRYPT_STRING_BASE64))


def main() -> int:
    args = parse_args()

    try:
        subject = build_subject(args)
        eku_oids = args.eku or DEFAULT_EKU_OIDS
        csr_b64 = generate_csr(
            subject=subject,
            eku_oids=eku_oids,
            provider_type=args.provider_type,
            provider_name=args.provider_name,
            pin=args.pin,
            include_subject_sign_tool=not args.no_subject_sign_tool,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(csr_b64)

    if args.pem_out:
        pem = (
            "-----BEGIN CERTIFICATE REQUEST-----\n"
            + chunk_64(csr_b64)
            + "\n-----END CERTIFICATE REQUEST-----\n"
        )
        with open(args.pem_out, "w", encoding="utf-8") as f:
            f.write(pem)

    print(csr_b64)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
