# -*- coding: utf-8 -*-
import argparse
import os
import sys


def save_chain_from_tst(token_der: bytes, out_prefix: str) -> list[str]:
    """
    Извлекает certificates из TimeStampToken (CMS SignedData) и сохраняет:
    - {out_prefix}.chain-N.cer (DER)
    - {out_prefix}.chain.pem (PEM, все сертификаты подряд)
    """
    from asn1crypto import pem
    from asn1crypto.cms import ContentInfo, SignedData

    ci = ContentInfo.load(token_der)
    sd = ci["content"]
    sd = sd.parsed if hasattr(sd, "parsed") else sd
    if not isinstance(sd, SignedData):
        sd = SignedData.load(sd.native)

    paths: list[str] = []
    certs = sd["certificates"]

    for i, c in enumerate(certs):
        cert = c.chosen  # x509.Certificate
        p = f"{out_prefix}.chain-{i}.cer"
        with open(p, "wb") as f:
            f.write(cert.dump())
        paths.append(p)

    pem_path = f"{out_prefix}.chain.pem"
    with open(pem_path, "wb") as f:
        for c in certs:
            cert = c.chosen
            f.write(pem.armor("CERTIFICATE", cert.dump()))
    paths.append(pem_path)

    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description="OCSP / TSP клиенты с ГОСТ")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ocsp = sub.add_parser("ocsp", help="OCSP-запрос (CertID по ГОСТ)")
    p_ocsp.add_argument("url")
    p_ocsp.add_argument("cert", help="Путь к PEM/DER проверяемого сертификата")
    p_ocsp.add_argument("issuer", help="Путь к PEM/DER сертификата издателя")
    p_ocsp.add_argument(
        "--digest",
        type=int,
        default=256,
        choices=(256, 512),
        help="Размер хеша ГОСТ для CertID",
    )
    p_ocsp.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="HTTP timeout (сек)",
    )

    p_tsp = sub.add_parser("tsp", help="TSP-запрос (MessageImprint по ГОСТ)")
    p_tsp.add_argument("url")
    p_tsp.add_argument("file", help="Файл для штампа времени")
    p_tsp.add_argument(
        "--digest",
        type=int,
        default=256,
        choices=(256, 512),
    )
    p_tsp.add_argument(
        "--nonce",
        type=int,
        default=None,
        help="Nonce (int). Если не задан, nonce не отправляется.",
    )

    args = parser.parse_args()

    if args.cmd == "ocsp":
        from asn1crypto import pem
        from asn1crypto import ocsp as asn1_ocsp
        from .ocsp_client import OCSPClient

        import re
        from pathlib import Path
        from urllib.parse import urlparse

        with open(args.cert, "rb") as f:
            data = f.read()
        _, _, data = pem.unarmor(data, multiple=False) if data.startswith(b"-----") else (None, None, data)
        with open(args.issuer, "rb") as f:
            idata = f.read()
        _, _, idata = pem.unarmor(idata, multiple=False) if idata.startswith(b"-----") else (None, None, idata)

        try:
            client = OCSPClient(args.url, timeout=args.timeout)
            raw, _http = client.request_raw(data, idata, digest_size=args.digest)
            o = asn1_ocsp.OCSPResponse.load(raw)
            response_status = o["response_status"].native

            # output paths
            p = urlparse(args.url)
            host = p.hostname or "unknown-host"
            path = (p.path or "").strip("/").replace("/", "_") or "ocsp"
            name = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{host}__{path}")[:120]
            out_dir = Path("output") / "ocsp" / host
            out_dir.mkdir(parents=True, exist_ok=True)
            raw_path = out_dir / f"{name}.ocsp-response.der"
            sig_path = out_dir / f"{name}.sig.bin"
            raw_path.write_bytes(raw)

            print("--- OCSP ---")
            print(f"URL:           {args.url}")
            print(f"Digest:        GOST 34.11-2012 ({args.digest})")
            print(f"ResponseStatus:{response_status}")
            print(f"Raw saved:     {raw_path}")

            cert_status: str | None = None
            if response_status == "successful" and o["response_bytes"].contents is not None:
                basic = o["response_bytes"]["response"].parsed
                sig = basic["signature"].native
                sig_path.write_bytes(sig)
                print(f"Sig saved:     {sig_path} ({len(sig)} bytes)")

                tbs = basic["tbs_response_data"]
                try:
                    responses = tbs["responses"]
                    if responses and len(responses):
                        cert_status = responses[0]["cert_status"].native
                except Exception:
                    cert_status = None
                rid = tbs["responder_id"]
                rid_s = rid.name
                if rid_s == "by_name":
                    rid_v = rid.chosen.human_friendly
                else:
                    rid_v = rid.chosen.native.hex()
                algo = basic["signature_algorithm"]["algorithm"].dotted
                print(f"ResponderID:   {rid_s}")
                print(f"ResponderID V: {rid_v}")
                print(f"Sig OID:       {algo}")

                certs = basic["certs"]
                if certs is not None and certs.contents is not None and len(certs):
                    print(f"Embedded certs: {len(certs)}")
                    for i, c in enumerate(certs):
                        der_p = out_dir / f"{name}.responder-{i}.cer"
                        pem_p = out_dir / f"{name}.responder-{i}.pem"
                        der_p.write_bytes(c.dump())
                        pem_p.write_bytes(pem.armor("CERTIFICATE", c.dump()))
                        print(f"  responder-{i}: {der_p}")
            if cert_status is not None:
                print(f"CertStatus:    {cert_status}")
            else:
                print("CertStatus:    -")
            print(f"Статус сертификата: {cert_status or '-'}")
        except Exception as e:
            print(f"Ошибка: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.cmd == "tsp":
        from .tsp_client import TSPClient

        with open(args.file, "rb") as f:
            payload = f.read()
        client = TSPClient(args.url)
        try:
            r = client.timestamp(payload, digest_size=args.digest, nonce=args.nonce)
            print("--- TSP ответ ---")
            print(f"URL:           {args.url}")
            print(f"Файл:          {args.file} ({len(payload)} байт)")
            print(f"Хеш:           ГОСТ Р 34.11-2012 ({args.digest})")
            print(f"PKI status:    {r.status}")
            if r.fail_info:
                print(f"Fail info:     {r.fail_info}")
            if r.tst_info is not None:
                ti = r.tst_info
                print("--- TSTInfo ---")
                print(f"  policy:      {ti['policy'].dotted}")
                print(f"  serial:      {ti['serial_number'].native}")
                print(f"  genTime:     {ti['gen_time'].native}")
                if ti["accuracy"].native is not None:
                    print(f"  accuracy:    {ti['accuracy'].native}")
                print(f"  ordering:    {ti['ordering'].native}")
                mi = ti["message_imprint"]
                print(f"  hash algo:   {mi['hash_algorithm']['algorithm'].dotted}")
                print(f"  hash len:    {len(mi['hashed_message'].native)} байт")
                if client.verify_imprint(payload, r, args.digest):
                    print("  verify:      MessageImprint совпадает с данными (ГОСТ)")
                else:
                    print("  verify:      MessageImprint не совпадает")
            if r.time_stamp_token_der:
                print(f"Размер токена: {len(r.time_stamp_token_der)} байт")
                out_dir = "output"
                os.makedirs(out_dir, exist_ok=True)
                stem = os.path.splitext(os.path.basename(args.file))[0] or "timestamp"
                token_path = os.path.join(out_dir, f"{stem}.tst")
                with open(token_path, "wb") as f:
                    f.write(r.time_stamp_token_der)
                print(f"Токен сохранён: {token_path}")
                out_prefix = os.path.splitext(token_path)[0]
                try:
                    saved = save_chain_from_tst(r.time_stamp_token_der, out_prefix)
                    print("Цепочка сохранена:")
                    for p in saved:
                        print(f"  {p}")
                except Exception as e:
                    print(f"Не удалось извлечь цепочку из токена: {e}")
            print(f"Размер ответа: {len(r.raw_response)} байт")
        except Exception as e:
            print(f"Ошибка: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
