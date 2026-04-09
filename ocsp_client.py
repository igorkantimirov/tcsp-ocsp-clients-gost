# -*- coding: utf-8 -*-
"""
Клиент OCSP с поддержкой ГОСТ Р 34.11-2012 для хешей в CertID.
"""

from __future__ import annotations

import base64
import datetime as _dt
import textwrap
import typing
from urllib.parse import urlparse

import requests
from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import x509
from asn1crypto.algos import DigestAlgorithm
from asn1crypto.core import Sequence
from asn1crypto.core import Void
from asn1crypto.ocsp import CertId, Request, TBSRequest, OCSPRequest
from asn1crypto.x509 import Certificate

from .gost_hash import gost_digest
from .gost_oids import gost_hash_oid


def _gost_hash(data: bytes, size: int = 256) -> bytes:
    return gost_digest(data, digest_size=size)


def _build_cert_id_gost(
    cert: Certificate,
    issuer_cert: Certificate,
    digest_size: int = 256,
) -> CertId:
    """Собирает CertID по ГОСТ Р 34.11-2012."""
    oid = gost_hash_oid(digest_size)
    issuer_name_der = issuer_cert["tbs_certificate"]["subject"].dump()
    spki_der = issuer_cert["tbs_certificate"]["subject_public_key_info"].dump()
    spki_seq = Sequence.load(spki_der)
    spk_bitstring = spki_seq[1]
    issuer_key_bytes = spk_bitstring.contents[1:]
    issuer_name_hash = _gost_hash(issuer_name_der, digest_size)
    issuer_key_hash = _gost_hash(issuer_key_bytes, digest_size)
    serial = cert["tbs_certificate"]["serial_number"].native

    digest_algo = DigestAlgorithm()
    digest_algo["algorithm"] = oid
    # digest_algo["parameters"] = Void()

    cert_id = CertId()
    cert_id["hash_algorithm"] = digest_algo
    cert_id["issuer_name_hash"] = issuer_name_hash
    cert_id["issuer_key_hash"] = issuer_key_hash
    cert_id["serial_number"] = serial
    return cert_id


def _parse_ocsp_response(raw: bytes) -> asn1_ocsp.OCSPResponse:
    return asn1_ocsp.OCSPResponse.load(raw)


def _safe_hex(b: typing.Optional[bytes], limit: int = 32) -> str:
    if b is None:
        return "-"
    if not b:
        return ""
    if len(b) <= limit:
        return b.hex()
    return f"{b[:limit].hex()}…(+{len(b) - limit} bytes)"


def _fmt_dt(v: typing.Any) -> str:
    if v is None:
        return "-"
    if isinstance(v, (str, int)):
        return str(v)
    if isinstance(v, _dt.datetime):
        return v.isoformat()
    return str(v)


def _oid_native_safe(oid_field: typing.Any) -> str:
    try:
        return oid_field.native
    except Exception:
        try:
            return oid_field.dotted
        except Exception:
            return str(oid_field)


def _get_extension(exts: typing.Any, oid_or_name: str) -> typing.Any | None:
    try:
        for ext in exts:
            extn_id = ext["extn_id"]
            if extn_id.native == oid_or_name or extn_id.dotted == oid_or_name:
                return ext
    except Exception:
        return None
    return None


class OCSPClient:
    """
    Клиент для запросов к OCSP-серверу с поддержкой ГОСТ в CertID.
    """

    def __init__(
        self,
        url: str,
        timeout: float = 10.0,
        session: typing.Optional[requests.Session] = None,
    ):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self._session = session or requests.Session()
        self._session.headers.setdefault(
            "Content-Type", "application/ocsp-request"
        )
        self._session.headers.setdefault("Accept", "application/ocsp-response")
        self._session.headers.setdefault(
            "User-Agent", "ocsp-client"
        )

    def build_request_der(
        self,
        cert: typing.Union[Certificate, bytes],
        issuer_cert: typing.Union[Certificate, bytes],
        digest_size: int = 256,
    ) -> bytes:
        if isinstance(cert, bytes):
            cert = Certificate.load(cert)
        if isinstance(issuer_cert, bytes):
            issuer_cert = Certificate.load(issuer_cert)

        cert_id = _build_cert_id_gost(cert, issuer_cert, digest_size)
        req = Request()
        req["req_cert"] = cert_id

        tbs = TBSRequest()
        tbs["version"] = "v1"
        tbs["request_list"] = [req]

        ocsp_req = OCSPRequest()
        ocsp_req["tbs_request"] = tbs
        return ocsp_req.dump()

    def request_raw(
        self,
        cert: typing.Union[Certificate, bytes],
        issuer_cert: typing.Union[Certificate, bytes],
        digest_size: int = 256,
    ) -> tuple[bytes, requests.Response]:
        request_der = self.build_request_der(cert, issuer_cert, digest_size)
        resp = self._session.post(
            self.url,
            data=request_der,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.content, resp

    def request(
        self,
        cert: typing.Union[Certificate, bytes],
        issuer_cert: typing.Union[Certificate, bytes],
        digest_size: int = 256,
    ) -> asn1_ocsp.OCSPResponse:
        """
        Отправляет OCSP-запрос для проверки статуса сертификата.

        :param cert: проверяемый сертификат (asn1crypto.x509.Certificate или DER)
        :param issuer_cert: сертификат издателя (для построения CertID)
        :param digest_size: размер хеша ГОСТ (256 или 512)
        :return: OCSPResponse
        """
        raw, _ = self.request_raw(cert, issuer_cert, digest_size)
        return _parse_ocsp_response(raw)

    def analyze_response(
        self,
        raw_response: bytes,
        http_response: typing.Optional[requests.Response] = None,
    ) -> str:
        parsed_url = urlparse(self.url)
        lines: list[str] = []
        lines.append("=== OCSP report ===")
        lines.append(f"URL: {self.url}")
        lines.append(f"Host: {parsed_url.hostname or '-'}")
        lines.append(f"Fetched at: {_dt.datetime.now().astimezone().isoformat()}")
        lines.append("")

        if http_response is not None:
            lines.append("--- HTTP ---")
            lines.append(f"Status: {http_response.status_code}")
            ct = http_response.headers.get("Content-Type", "-")
            lines.append(f"Content-Type: {ct}")
            lines.append(f"Content-Length: {len(raw_response)}")
            lines.append(f"First-bytes(hex): {_safe_hex(raw_response, 32)}")
            lines.append("")

        try:
            ocsp = _parse_ocsp_response(raw_response)
        except Exception as e:
            lines.append("--- Parse ---")
            lines.append(f"Failed to parse OCSPResponse: {e}")
            lines.append(f"Raw(base64, first 256): {base64.b64encode(raw_response[:256]).decode('ascii')}")
            return "\n".join(lines) + "\n"

        lines.append("--- OCSPResponse ---")
        lines.append(f"response_status: {ocsp['response_status'].native}")
        rb = ocsp["response_bytes"]
        has_rb = False
        try:
            has_rb = rb is not None and rb.contents is not None
        except Exception:
            has_rb = False
        lines.append(f"has_response_bytes: {has_rb}")
        if not has_rb:
            return "\n".join(lines) + "\n"

        lines.append(f"response_type(OID): {rb['response_type'].dotted}")
        lines.append("")

        try:
            basic = rb["response"].parsed  # BasicOCSPResponse
        except Exception as e:
            lines.append("--- BasicOCSPResponse ---")
            lines.append(f"Failed to parse BasicOCSPResponse: {type(e).__name__}: {e!r}")
            lines.append(f"Raw OCSPResponse len: {len(raw_response)}")
            lines.append(f"Raw OCSPResponse first-bytes(hex): {_safe_hex(raw_response, 64)}")
            lines.append(f"Raw OCSPResponse(base64, first 256): {base64.b64encode(raw_response[:256]).decode('ascii')}")
            lines.append("")
            return "\n".join(lines) + "\n"

        lines.append("--- BasicOCSPResponse ---")
        try:
            sig_algo = basic["signature_algorithm"]
            lines.append(f"signature_algorithm(native): {_oid_native_safe(sig_algo['algorithm'])}")
            try:
                lines.append(f"signature_algorithm(OID): {sig_algo['algorithm'].dotted}")
            except Exception:
                lines.append("signature_algorithm(OID): -")
        except Exception as e:
            lines.append(f"signature_algorithm: (failed to read) {type(e).__name__}: {e!r}")
        try:
            sig_bytes = basic["signature"].native
            lines.append(f"signature_len: {len(sig_bytes)}")
            lines.append(f"signature_first_bytes(hex): {_safe_hex(sig_bytes, 32)}")
        except Exception as e:
            lines.append(f"signature: (failed to read) {type(e).__name__}: {e!r}")
        lines.append("")

        try:
            tbs = basic["tbs_response_data"]
            lines.append("--- tbsResponseData (signed) ---")
            lines.append(f"version: {tbs['version'].native}")
            rid = tbs["responder_id"]
            lines.append(f"responder_id.type: {rid.name}")
            if rid.name == "by_name":
                try:
                    lines.append(f"responder_id.by_name: {rid.chosen.human_friendly}")
                except Exception as e:
                    lines.append(f"responder_id.by_name: (failed) {type(e).__name__}: {e!r}")
            else:
                # by_key: OCTET STRING
                try:
                    rid_bytes = rid.chosen.native
                except Exception:
                    rid_bytes = None
                lines.append(f"responder_id.by_key(hex): {_safe_hex(rid_bytes, 64)}")
            lines.append(f"produced_at: {_fmt_dt(tbs['produced_at'].native)}")
            lines.append(f"responses_count: {len(tbs['responses'])}")
            lines.append(
                f"tbsResponseData_der_sha256: {__import__('hashlib').sha256(tbs.dump()).hexdigest()}"
            )
            lines.append("")
        except Exception as e:
            lines.append("--- tbsResponseData (signed) ---")
            lines.append(f"Failed to parse tbsResponseData: {type(e).__name__}: {e!r}")
            lines.append("")
            return "\n".join(lines) + "\n"

        # SingleResponse details (first)
        try:
            responses = tbs["responses"]
            if len(responses):
                sr0 = responses[0]
                lines.append("--- SingleResponse[0] ---")
                cid = sr0["cert_id"]
                lines.append(
                    f"cert_id.hash_algorithm(native): {_oid_native_safe(cid['hash_algorithm']['algorithm'])}"
                )
                try:
                    lines.append(f"cert_id.hash_algorithm(OID): {cid['hash_algorithm']['algorithm'].dotted}")
                except Exception:
                    lines.append("cert_id.hash_algorithm(OID): -")
                lines.append(
                    f"cert_id.issuer_name_hash(hex): {_safe_hex(cid['issuer_name_hash'].native, 64)}"
                )
                lines.append(
                    f"cert_id.issuer_key_hash(hex): {_safe_hex(cid['issuer_key_hash'].native, 64)}"
                )
                lines.append(f"cert_id.serial_number: {cid['serial_number'].native}")
                lines.append(f"cert_status: {sr0['cert_status'].native}")
                lines.append(f"this_update: {_fmt_dt(sr0['this_update'].native)}")
                nu = sr0["next_update"].native
                lines.append(f"next_update: {_fmt_dt(nu)}")
                if sr0["cert_status"].name == "revoked":
                    rev = sr0["cert_status"].chosen
                    lines.append(f"revocation_time: {_fmt_dt(rev['revocation_time'].native)}")
                    lines.append(f"revocation_reason: {rev['revocation_reason'].native}")
                lines.append("")
        except Exception as e:
            lines.append("--- SingleResponse[0] ---")
            lines.append(f"Failed to parse SingleResponse: {type(e).__name__}: {e!r}")
            lines.append("")

        # Embedded certs
        certs_present = False
        try:
            certs_present = basic["certs"] is not None and basic["certs"].contents is not None
        except Exception:
            certs_present = False
        lines.append("--- Embedded certs ---")
        if not certs_present:
            lines.append("certs: (absent)")
        else:
            cert_list = basic["certs"]
            lines.append(f"certs_count: {len(cert_list)}")
            for i, c in enumerate(cert_list):
                try:
                    subj = c["tbs_certificate"]["subject"].human_friendly
                except Exception:
                    subj = str(c["tbs_certificate"]["subject"].native)
                serial = c["tbs_certificate"]["serial_number"].native
                issuer = c["tbs_certificate"]["issuer"].human_friendly
                lines.append(f"[{i}] subject: {subj}")
                lines.append(f"    issuer:  {issuer}")
                lines.append(f"    serial:  {serial}")
                # EKU (если есть)
                try:
                    exts = c["tbs_certificate"]["extensions"]
                except Exception:
                    exts = None
                if exts is not None:
                    eku_ext = _get_extension(exts, "extended_key_usage") or _get_extension(
                        exts, "2.5.29.37"
                    )
                    if eku_ext is not None:
                        lines.append(f"    eku:     {eku_ext['extn_value'].native}")
        lines.append("")

        wrapped: list[str] = []
        for ln in lines:
            if ln.startswith("responder_id.by_name: "):
                wrapped.extend(textwrap.wrap(ln, width=120, subsequent_indent=" " * 4))
            else:
                wrapped.append(ln)

        return "\n".join(wrapped) + "\n"

    def check_status(
        self,
        cert: typing.Union[Certificate, bytes],
        issuer_cert: typing.Union[Certificate, bytes],
        digest_size: int = 256,
    ) -> str:
        """
        Запрашивает статус и возвращает одно из: 'good', 'revoked', 'unknown'.

        :return: 'good' | 'revoked' | 'unknown'
        """
        response = self.request(cert, issuer_cert, digest_size)
        status_enum = response["response_status"].native
        if status_enum != "successful":
            raise OCSPError(f"OCSP response status: {status_enum}")

        basic = response["response_bytes"]["response"].parsed
        responses = basic["tbs_response_data"]["responses"]
        if not responses:
            raise OCSPError("Нет SingleResponse в ответе")
        cert_status = responses[0]["cert_status"].native
        return cert_status


class OCSPError(Exception):
    """Ошибка при запросе или разборе OCSP."""
    pass
