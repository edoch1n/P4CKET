"""Analiz ozeti modeli."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from p4cket.modeller.tehdit_bulgusu import TehditBulgusu
from p4cket.modeller.tehdit_seviyesi import TehditSeviyesi


@dataclass
class AnalizOzeti:
    pcap_dosya: str
    analiz_zamani: str
    toplam_paket: int
    benzersiz_host: int
    tcp_akislari: int
    udp_akislari: int
    icmp_paketleri: int
    dns_paketleri: int
    bulgular: list[TehditBulgusu]
    genel_risk_puani: int
    tehdit_seviyesi: TehditSeviyesi
    oneriler: list[str] = field(default_factory=list)
