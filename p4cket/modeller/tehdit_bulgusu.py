"""Tehdit bulgusu modeli."""

from dataclasses import dataclass, field
from typing import Optional

from p4cket.modeller.tehdit_seviyesi import TehditSeviyesi


@dataclass
class TehditBulgusu:
    tespit_turu: str
    baslik: str
    aciklama: str
    seviye: TehditSeviyesi
    puan: int
    guven: float
    kaynak: str
    hedef: Optional[str] = None
    kanit: dict = field(default_factory=dict)
    zaman: Optional[float] = None
    onerilen_aksiyon: str = ""
