"""Ag akisi modeli."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgAkisi:
    akis_id: str
    kaynak_ip: str
    hedef_ip: str
    kaynak_port: Optional[int]
    hedef_port: Optional[int]
    protokol: str
    paket_sayisi: int = 0
    bayt_sayisi: int = 0
    ilk_gorulme: float = 0.0
    son_gorulme: float = 0.0
    zaman_damgalari: list[float] = field(default_factory=list)
    tcp_bayraklari: list[str] = field(default_factory=list)
    syn_sayisi: int = 0
    syn_ack_sayisi: int = 0
    fin_sayisi: int = 0
    rst_sayisi: int = 0
    baglanti_denemeleri: int = 0
