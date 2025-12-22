# -*- coding: utf-8 -*-
"""
OID и утилиты для ГОСТ Р 34.10-2012, 34.11-2012 (RFC 7091, 6986).
"""

# ГОСТ Р 34.11-2012
OID_GOST_R_34_11_2012_256 = "1.2.643.7.1.1.2.2"
OID_GOST_R_34_11_2012_512 = "1.2.643.7.1.1.2.3"

# ГОСТ Р 34.10-2012 подпись
OID_GOST_R_34_10_2012_256 = "1.2.643.7.1.1.3.2"
OID_GOST_R_34_10_2012_512 = "1.2.643.7.1.1.3.3"

# id-tc26-gost3411-12 (другое представление)
OID_TC26_GOST3411_12_256 = OID_GOST_R_34_11_2012_256
OID_TC26_GOST3411_12_512 = OID_GOST_R_34_11_2012_512


def gost_hash_oid(digest_size: int = 256) -> str:
    """OID алгоритма хеширования ГОСТ в зависимости от размера (256 или 512)."""
    return OID_GOST_R_34_11_2012_512 if digest_size == 512 else OID_GOST_R_34_11_2012_256


def is_gost_digest_oid(oid: str) -> bool:
    return oid in (OID_GOST_R_34_11_2012_256, OID_GOST_R_34_11_2012_512)


def is_gost_signature_oid(oid: str) -> bool:
    return oid in (OID_GOST_R_34_10_2012_256, OID_GOST_R_34_10_2012_512)
