"""Tehdit seviyesi enum."""

from enum import Enum


class TehditSeviyesi(str, Enum):
    DUSUK = "DÜŞÜK"
    ORTA = "ORTA"
    YUKSEK = "YÜKSEK"
    KRITIK = "KRİTİK"
