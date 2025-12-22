# -*- coding: utf-8 -*-
"""
Клиент OCSP с поддержкой ГОСТ Р 34.11-2012 для хешей в CertID.
"""

from __future__ import annotations

import typing

import requests
from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import x509
from asn1crypto.algos import DigestAlgorithm
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
    issuer_key_der = issuer_cert["tbs_certificate"]["subject_public_key_info"].dump()
    issuer_name_hash = _gost_hash(issuer_name_der, digest_size)
    issuer_key_hash = _gost_hash(issuer_key_der, digest_size)
    serial = cert["tbs_certificate"]["serial_number"].native

    digest_algo = DigestAlgorithm()
    digest_algo["algorithm"] = oid
    digest_algo["parameters"] = Void()

    cert_id = CertId()
    cert_id["hash_algorithm"] = digest_algo
    cert_id["issuer_name_hash"] = issuer_name_hash
    cert_id["issuer_key_hash"] = issuer_key_hash
    cert_id["serial_number"] = serial
    return cert_id


def _parse_ocsp_response(raw: bytes) -> asn1_ocsp.OCSPResponse:
    return asn1_ocsp.OCSPResponse.load(raw)


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

        request_der = ocsp_req.dump()

        resp = self._session.post(
            self.url,
            data=request_der,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return _parse_ocsp_response(resp.content)

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
