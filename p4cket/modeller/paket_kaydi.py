"""Paket kaydi modeli."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class PaketKaydi:
    zaman_damgasi: float
    kaynak_ip: str
    hedef_ip: str
    protokol: str
    kaynak_port: Optional[int] = None
    hedef_port: Optional[int] = None
    uzunluk: int = 0
    tcp_bayraklari: Optional[str] = None
    dns_sorgusu: Optional[str] = None
    dns_cevabi: Optional[str] = None
    dns_sorgu_tipi: Optional[str] = None
    icmp_tipi: Optional[int] = None
    icmp_kodu: Optional[int] = None
