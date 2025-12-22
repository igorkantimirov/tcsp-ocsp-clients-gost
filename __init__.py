# -*- coding: utf-8 -*-
"""
Клиенты TSP и OCSP с поддержкой ГОСТ (Python).
"""

from .ocsp_client import OCSPClient
from .tsp_client import TSPClient

__all__ = ["OCSPClient", "TSPClient"]
