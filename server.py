#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP API поверх OpenSSL с engine gost (образ mini-pki-gost).

Переменные окружения (по умолчанию пути в /data):
  CA_CERT, CA_KEY       — УЦ для подписи CSR
  CA_SERIAL             — файл серийного номера (openssl -CAserial)
  INDEX                 — index.txt для OCSP
  OCSP_CERT, OCSP_KEY   — подпись ответа OCSP
  OCSP_CA               — -CA для responder (часто = CA_CERT)
  OCSP_ISSUER           — -issuer (часто = CA_CERT)
  TSA_CONFIG            — openssl.cnf с секцией [tsa] / [tsa1]

Эндпойнты:
  GET  /health
  POST /sign-csr       — CSR base64(DER) → leaf .cer (DER X.509) выдача сертификата
  POST /ocsp           — сырой OCSP request (DER), ответ application/ocsp-response
  POST /tsp            — сырой TimeStampReq (DER), ответ application/timestamp-reply
"""

from __future__ import annotations

import email.utils
import base64
import binascii
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request, Response

app = FastAPI(title="mini-pki-gost OpenSSL API", version="0.1.0")


def _env_path(key: str, default: str) -> Path:
    return Path(os.environ.get(key, default))


CA_CERT = _env_path("CA_CERT", "/data/ca.cert.pem")
CA_KEY = _env_path("CA_KEY", "/data/ca.key.pem")
CA_SERIAL = _env_path("CA_SERIAL", "/data/ca.srl")
INDEX = _env_path("INDEX", "/data/index.txt")
OCSP_CERT = _env_path("OCSP_CERT", "/data/ocsp.cert.pem")
OCSP_KEY = _env_path("OCSP_KEY", "/data/ocsp.key.pem")
OCSP_CA = _env_path("OCSP_CA", "/data/ca.cert.pem")
OCSP_ISSUER = _env_path("OCSP_ISSUER", "/data/ca.cert.pem")
TSA_CONFIG = _env_path("TSA_CONFIG", "/data/tsa/openssl-tsa.cnf")
CA_CRL_CONFIG = _env_path("CA_CRL_CONFIG", "/data/openssl-ca.cnf")
CA_CRL_NUMBER = _env_path("CA_CRL_NUMBER", "/data/crlnumber")
# Дни по умолчанию для выданного сертификата
CERT_DAYS = int(os.environ.get("CERT_DAYS", "365"))


def _run_openssl(args: list[str], stdin: bytes | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.setdefault("OPENSSL_ENGINES", "/usr/lib/x86_64-linux-gnu/engines-3")
    env.setdefault("OPENSSL_CONF", "/etc/ssl/openssl-gost.cnf")
    return subprocess.run(
        ["openssl", *args],
        input=stdin,
        capture_output=True,
        env=env,
        check=False,
    )


def _require_file(p: Path, name: str) -> None:
    if not p.is_file():
        raise HTTPException(503, detail=f"Нет файла {name}: {p}")


EE_EXT = """basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
"""

def _default_public_url(request: Request, path: str) -> str:
    """
    Строит публичный URL по headers (учитывает типичный reverse-proxy),
    чтобы AIA OCSP/caIssuers был кликабельным.
    """
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    base = f"{proto}://{host}".rstrip("/")
    return base + (path if path.startswith("/") else f"/{path}")


def _parse_x509_meta(cert_pem: bytes) -> tuple[str, str, str]:
    """serial hex, index expiry YYMMDDhhmmssZ, subject one line for index."""
    p = _run_openssl(
        [
            "x509",
            "-noout",
            "-serial",
            "-enddate",
            "-subject",
            "-nameopt",
            "esc_2253,utf8,-esc_msb",
        ],
        stdin=cert_pem,
    )
    if p.returncode != 0:
        raise HTTPException(500, detail=p.stderr.decode("utf-8", errors="replace")[:2000])
    text = p.stdout.decode("utf-8", errors="replace")
    serial_m = re.search(r"^serial=(.+)$", text, re.M)
    end_m = re.search(r"^notAfter=(.+)$", text, re.M)
    subj_m = re.search(r"^subject=(.+)$", text, re.M)
    if not serial_m or not end_m or not subj_m:
        raise HTTPException(500, detail="Не разобрали вывод openssl x509")
    serial = serial_m.group(1).strip().upper().replace(":", "")
    not_after = end_m.group(1).strip()
    subject = subj_m.group(1).strip()
    # notAfter=Apr 19 05:28:33 2026 GMT
    dt = email.utils.parsedate_to_datetime(not_after)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    exp = dt.strftime("%y%m%d%H%M%SZ")
    if not subject.startswith("/"):
        subject = "/" + subject.replace(", ", "/").replace(",", "/")
    return serial, exp, subject


def _append_index(cert_pem: bytes) -> None:
    serial, exp, subject = _parse_x509_meta(cert_pem)
    line = f"V\t{exp}\t\t{serial}\tunknown\t{subject}\n"
    INDEX.parent.mkdir(parents=True, exist_ok=True)
    # OpenSSL `ocsp -index` строит "name index" по subject и может падать,
    # если в index.txt несколько валидных (V) записей с одинаковым subject.
    # В демо-режиме проще "снимать" предыдущую валидную запись с тем же subject.
    if INDEX.is_file():
        prev = INDEX.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    else:
        prev = []

    out: list[str] = []
    for l in prev:
        parts = l.rstrip("\n").split("\t")
        if len(parts) < 6:
            # не трогаем мусор/пустые строки — пусть остаются как есть
            out.append(l)
            continue
        status, _exp, _rev, _serial, _file, subj = parts[:6]
        if status == "V" and subj == subject:
            # Помечаем как revoked "сейчас" (YYMMDDHHMMSSZ), чтобы уникальность subject восстановилась.
            now = datetime.now(timezone.utc).strftime("%y%m%d%H%M%SZ")
            parts[0] = "R"
            parts[2] = now
            out.append("\t".join(parts) + "\n")
            continue
        out.append(l)

    out.append(line)
    INDEX.write_text("".join(out), encoding="utf-8")


def _ocsp_reply(req_der: bytes) -> bytes:
    if not req_der:
        raise HTTPException(400, detail="Пустое тело")
    _require_file(INDEX, "INDEX")
    _require_file(OCSP_CA, "OCSP_CA")
    _require_file(OCSP_ISSUER, "OCSP_ISSUER")
    _require_file(OCSP_CERT, "OCSP_CERT")
    _require_file(OCSP_KEY, "OCSP_KEY")

    with tempfile.TemporaryDirectory(prefix="ocsp-") as tmp:
        td = Path(tmp)
        req = td / "req.der"
        resp = td / "resp.der"
        req.write_bytes(req_der)
        p = _run_openssl(
            [
                "ocsp",
                "-index",
                str(INDEX),
                "-CA",
                str(OCSP_CA),
                "-issuer",
                str(OCSP_ISSUER),
                # ResponderId (?) by_name.
                "-resp_key_id",
                "-rsigner",
                str(OCSP_CERT),
                "-rkey",
                str(OCSP_KEY),
                "-reqin",
                str(req),
                "-respout",
                str(resp),
                "-ndays",
                "7",
            ]
        )
        if p.returncode != 0 or not resp.is_file():
            raise HTTPException(
                502,
                detail=p.stderr.decode("utf-8", errors="replace")[:4000] or "openssl ocsp failed",
            )
        return resp.read_bytes()


@app.get("/health")
def health() -> dict:
    v = _run_openssl(["version"])
    eng = _run_openssl(["engine", "-c", "-t"])
    ok = v.returncode == 0 and eng.returncode == 0 and b"gost" in eng.stdout.lower()
    return {
        "ok": ok,
        "openssl": v.stdout.decode().strip() if v.stdout else "",
        "gost_engine": "gost" in eng.stdout.decode(errors="replace").lower(),
    }


@app.get("/ca.cer")
def get_ca_cer() -> Response:
    _require_file(CA_CERT, "CA_CERT")
    data = CA_CERT.read_bytes()
    # Если CA_CERT уже DER (не PEM), просто отдаём как .cer
    if not data.startswith(b"-----BEGIN"):
        return Response(
            content=data,
            media_type="application/pkix-cert",
            headers={"Content-Disposition": "attachment; filename=ca.cer"},
        )

    # CA_CERT в PEM; конвертим в DER
    p = _run_openssl(["x509", "-in", str(CA_CERT), "-inform", "PEM", "-outform", "DER"])
    if p.returncode != 0 or not p.stdout:
        raise HTTPException(
            500,
            detail=p.stderr.decode("utf-8", errors="replace")[:4000] or "openssl x509 failed",
        )
    return Response(
        content=p.stdout,
        media_type="application/pkix-cert",
        headers={"Content-Disposition": "attachment; filename=ca.cer"},
    )


@app.get("/crl.crl")
def get_crl() -> Response:
    """
    Отдаёт CRL (DER), чтобы клиенты (в т.ч. JCPRevCheck) могли проверить отзыв по CRLDP.
    CRL генерируется из INDEX через `openssl ca -gencrl`.
    """
    _require_file(CA_CRL_CONFIG, "CA_CRL_CONFIG")
    _require_file(CA_CERT, "CA_CERT")
    _require_file(CA_KEY, "CA_KEY")
    _require_file(INDEX, "INDEX")
    _require_file(CA_CRL_NUMBER, "CA_CRL_NUMBER")

    with tempfile.TemporaryDirectory(prefix="crl-") as tmp:
        td = Path(tmp)
        crl_pem = td / "ca.crl.pem"
        p = _run_openssl(["ca", "-gencrl", "-config", str(CA_CRL_CONFIG), "-out", str(crl_pem)])
        if p.returncode != 0 or not crl_pem.is_file():
            raise HTTPException(502, detail=p.stderr.decode("utf-8", errors="replace")[:4000] or "openssl ca -gencrl failed")
        conv = _run_openssl(["crl", "-in", str(crl_pem), "-inform", "PEM", "-outform", "DER"])
        if conv.returncode != 0 or not conv.stdout:
            raise HTTPException(502, detail=conv.stderr.decode("utf-8", errors="replace")[:4000] or "openssl crl convert failed")
        return Response(
            content=conv.stdout,
            media_type="application/pkix-crl",
            headers={"Content-Disposition": "attachment; filename=ca.crl"},
        )


@app.post("/sign-csr")
async def sign_csr(
    request: Request,
    csr_b64: str = Form(description="CSR base64 (DER), без BEGIN/END"),
    ocsp_url: str | None = Form(default=None, description="AIA OCSP URL (если не задано — возьмём URL этого сервера + /ocsp)"),
    ca_issuers_url: str | None = Form(default=None, description="AIA caIssuers URL (если не задано — /ca.cer)"),
    crl_url: str | None = Form(default=None, description="CRLDP URL (если не задано — /crl.crl)"),
) -> Response:
    _require_file(CA_CERT, "CA_CERT")
    _require_file(CA_KEY, "CA_KEY")
    _ = request  # swagger-only form endpoint; raw body не используем
    # В application/x-www-form-urlencoded символ '+' часто превращается в пробел.
    # Чтобы curl -d 'csr_b64=...' работал даже если '+' не был percent-encoded,
    # восстанавливаем пробелы обратно в '+' перед base64 decode.
    raw = (csr_b64 or "").strip().replace(" ", "+")
    s = re.sub(r"\s+", "", raw)
    if not s:
        raise HTTPException(400, detail="csr_b64: пусто")
    try:
        csr_der = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError) as e:
        raise HTTPException(400, detail=f"csr_b64: не похоже на base64 DER: {e}") from e

    with tempfile.TemporaryDirectory(prefix="csr-") as tmp:
        td = Path(tmp)
        csr_path = td / "req.csr"
        ext_path = td / "ext.cnf"
        leaf_der_path = td / "leaf.cer"
        leaf_pem_path = td / "leaf.pem"

        csr_path.write_bytes(csr_der)
        ocsp = (ocsp_url or os.environ.get("OCSP_URL") or _default_public_url(request, "/ocsp")).strip()
        # caIssuers по умолчанию указывает на /ca.cer (может отдавать TRUST_ROOT_CERT, если он лежит в /data)
        ca_issuers = (ca_issuers_url or os.environ.get("CA_ISSUERS_URL") or _default_public_url(request, "/ca.cer")).strip()
        crl = (crl_url or os.environ.get("CRL_URL") or _default_public_url(request, "/crl.crl")).strip()
        # OpenSSL config syntax: authorityInfoAccess = OCSP;URI:...,caIssuers;URI:...
        ext_text = EE_EXT
        if ocsp:
            aia_parts = [f"OCSP;URI:{ocsp}"]
            if ca_issuers:
                aia_parts.append(f"caIssuers;URI:{ca_issuers}")
            ext_text += "authorityInfoAccess=" + ",".join(aia_parts) + "\n"
        if crl:
            # RFC 5280 CRL Distribution Points
            ext_text += f"crlDistributionPoints=URI:{crl}\n"
        ext_path.write_text(ext_text, encoding="utf-8")

        args = [
            "x509",
            "-req",
            "-engine",
            "gost",
            "-inform",
            "DER",
            "-in",
            str(csr_path),
            "-CA",
            str(CA_CERT),
            "-CAkey",
            str(CA_KEY),
        ]
        if CA_SERIAL.is_file():
            args.extend(["-CAserial", str(CA_SERIAL)])
        else:
            args.append("-CAcreateserial")
        args.extend(
            [
                "-out",
                str(leaf_der_path),
                "-outform",
                "DER",
                "-days",
                str(CERT_DAYS),
                "-extfile",
                str(ext_path),
            ]
        )

        p = _run_openssl(args)
        if p.returncode != 0:
            raise HTTPException(
                400,
                detail=p.stderr.decode("utf-8", errors="replace")[:4000] or "openssl x509 failed",
            )

        leaf_der = leaf_der_path.read_bytes()

        # Для index.txt (OCSP) парсим метаданные из PEM
        conv = _run_openssl(["x509", "-inform", "DER", "-outform", "PEM"], stdin=leaf_der)
        if conv.returncode != 0:
            raise HTTPException(500, detail=conv.stderr.decode("utf-8", errors="replace")[:2000])
        leaf_pem_path.write_bytes(conv.stdout)
        try:
            _append_index(conv.stdout)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, detail=f"index.txt: {e}") from e
        cert_bytes = leaf_der

    return Response(
        content=cert_bytes,
        media_type="application/pkix-cert",
        headers={"Content-Disposition": "attachment; filename=issued.cer"},
    )


@app.post("/ocsp")
async def ocsp_endpoint(request: Request) -> Response:
    body = await request.body()
    out = _ocsp_reply(body)
    return Response(content=out, media_type="application/ocsp-response")


@app.post("/tsp")
async def tsp_endpoint(request: Request) -> Response:
    body = await request.body()
    if not body:
        raise HTTPException(400, detail="Пустое тело")
    _require_file(TSA_CONFIG, "TSA_CONFIG")

    with tempfile.TemporaryDirectory(prefix="tsp-") as tmp:
        td = Path(tmp)
        q = td / "q.tsq"
        r = td / "r.tsr"
        q.write_bytes(body)
        p = _run_openssl(
            [
                "ts",
                "-reply",
                "-queryfile",
                str(q),
                "-config",
                str(TSA_CONFIG),
                "-section",
                "tsa1",
                "-out",
                str(r),
            ]
        )
        if p.returncode != 0 or not r.is_file():
            raise HTTPException(
                502,
                detail=p.stderr.decode("utf-8", errors="replace")[:4000] or "openssl ts -reply failed",
            )
        out = r.read_bytes()
    return Response(content=out, media_type="application/timestamp-reply")
