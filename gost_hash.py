# -*- coding: utf-8 -*-
"""Хеш ГОСТ Р 34.11-2012 gostcrypto или pygost."""

from __future__ import annotations


def gost_digest(data: bytes, digest_size: int = 256) -> bytes:
    """
    Возвращает digest
    """
    if digest_size not in (256, 512):
        raise ValueError("digest_size должен быть 256 или 512")

    try:
        import gostcrypto

        name = "streebog256" if digest_size == 256 else "streebog512"
        h = gostcrypto.gosthash.new(name, data=data)
        return bytes(h.digest())
    except ImportError:
        pass

    try:
        from pygost import gost34112012

        return gost34112012.GOST34112012(data, digest_size=digest_size).digest()
    except ImportError:
        pass

    raise RuntimeError(
        "Нужен gostcrypto или pygost. Установите: pip install gostcrypto"
    )
