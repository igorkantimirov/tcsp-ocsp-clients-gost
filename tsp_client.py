# -*- coding: utf-8 -*-
"""
Клиент TSP (RFC 3161) с поддержкой ГОСТ Р 34.11-2012 в MessageImprint.
"""

from __future__ import annotations

import typing

import requests
from asn1crypto.algos import DigestAlgorithm
from asn1crypto.cms import ContentInfo
from asn1crypto.core import Void
from asn1crypto.tsp import MessageImprint, TimeStampReq, TimeStampResp

from .gost_hash import gost_digest
from .gost_oids import gost_hash_oid


def _gost_hash(data: bytes, digest_size: int = 256) -> bytes:
    return gost_digest(data, digest_size=digest_size)


def _build_message_imprint(data: bytes, digest_size: int = 256) -> MessageImprint:
    oid = gost_hash_oid(digest_size)
    digest_algo = DigestAlgorithm()
    digest_algo["algorithm"] = oid
    digest_algo["parameters"] = Void()
    mi = MessageImprint()
    mi["hash_algorithm"] = digest_algo
    mi["hashed_message"] = _gost_hash(data, digest_size)
    return mi


def _build_timestamp_request(
    data: bytes,
    digest_size: int = 256,
    cert_req: bool = True,
    nonce: typing.Optional[int] = None,
) -> TimeStampReq:
    req = TimeStampReq()
    req["version"] = 1
    req["message_imprint"] = _build_message_imprint(data, digest_size)
    req["cert_req"] = cert_req
    if nonce is not None:
        req["nonce"] = nonce
    return req


class TSPClient:
    """
    Клиент для запросов к TSP (Time-Stamp Authority) с MessageImprint по ГОСТ.
    """

    def __init__(
        self,
        url: str,
        timeout: float = 30.0,
        session: typing.Optional[requests.Session] = None,
    ):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self._session = session or requests.Session()
        self._session.headers.setdefault(
            "Content-Type", "application/timestamp-query"
        )
        self._session.headers.setdefault("Accept", "application/timestamp-reply")

    def request(
        self,
        data: bytes,
        digest_size: int = 256,
        cert_req: bool = True,
        nonce: typing.Optional[int] = None,
    ) -> TimeStampResp:
        """
        Отправляет TimeStampReq с хешем данных по ГОСТ Р 34.11-2012.

        :param data: данные для штампа (хешируются)
        :param digest_size: 256 или 512
        :param cert_req: запросить цепочку сертификатов в ответе
        :param nonce: опциональный nonce (целое число)
        """
        ts_req = _build_timestamp_request(data, digest_size, cert_req, nonce)
        body = ts_req.dump()
        resp = self._session.post(
            self.url,
            data=body,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return TimeStampResp.load(resp.content)

    def timestamp(
        self,
        data: bytes,
        digest_size: int = 256,
        cert_req: bool = True,
        nonce: typing.Optional[int] = None,
    ) -> TSPResult:
        """
        Запрос штампа времени; возвращает разобранный результат.
        """
        ts_resp = self.request(data, digest_size, cert_req, nonce)
        status = ts_resp["status"]["status"].native
        fail_info = None
        if ts_resp["status"]["fail_info"].native is not None:
            fail_info = ts_resp["status"]["fail_info"].native
        token_der: typing.Optional[bytes] = None
        tst_info = None
        if status in ("granted", "granted_with_mods"):
            ci = ts_resp["time_stamp_token"]
            token_der = ci.dump()
            try:
                tst_info = _extract_tst_info(ci)
            except (TSPError, ValueError, KeyError, TypeError):
                tst_info = None
        return TSPResult(
            status=status,
            fail_info=fail_info,
            time_stamp_token_der=token_der,
            tst_info=tst_info,
            raw_response=ts_resp.dump(),
        )

    def verify_imprint(
        self,
        data: bytes,
        result: TSPResult,
        digest_size: int = 256,
    ) -> bool:
        """
        Проверяет, что в TSTInfo message_imprint совпадает с хешем данных (ГОСТ).
        Не проверяет подпись токена (для этого нужен КриптоПро / отдельная CMS-верификация).
        """
        if result.tst_info is None:
            return False
        expected = _gost_hash(data, digest_size)
        got = result.tst_info["message_imprint"]["hashed_message"].native
        return got == expected


def _extract_tst_info(content_info: ContentInfo) -> typing.Any:
    """Извлекает TSTInfo из ContentInfo (signedData -> eContent)."""
    from asn1crypto.cms import SignedData

    content_type = content_info["content_type"].native
    if content_type != "signed_data":
        raise TSPError(f"Неожиданный content_type токена: {content_type}")
    raw_content = content_info["content"]
    signed = raw_content.parsed if hasattr(raw_content, "parsed") else raw_content
    if not isinstance(signed, SignedData):
        signed = SignedData.load(raw_content.native)
    encap = signed["encap_content_info"]
    econtent = encap["content"].native
    if econtent is None:
        raise TSPError("Пустой eContent в TimeStampToken")
    from asn1crypto.tsp import TSTInfo

    return TSTInfo.load(econtent)


class TSPResult(typing.NamedTuple):
    status: str
    fail_info: typing.Optional[str]
    time_stamp_token_der: typing.Optional[bytes]
    tst_info: typing.Any
    raw_response: bytes


class TSPError(Exception):
    pass
