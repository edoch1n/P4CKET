import logging
from collections import defaultdict
from typing import Optional

from p4cket.modeller import AgAkisi, TehditBulgusu, TehditSeviyesi
from p4cket.yardimci.sabitler import TrafikAnomalisiSabitleri

logger = logging.getLogger(__name__)


class IcmpAnomalisiTespit:
    def __init__(self, sabitler: Optional[TrafikAnomalisiSabitleri] = None):
        self.sabitler = sabitler or TrafikAnomalisiSabitleri()

    def calistir(self, akislar: list[AgAkisi]) -> list[TehditBulgusu]:
        bulgular: list[TehditBulgusu] = []
        icmp_akislar: dict[tuple[str, str], list[AgAkisi]] = defaultdict(list)

        for akis in akislar:
            if akis.protokol == "ICMP":
                anahtar = (akis.kaynak_ip, akis.hedef_ip)
                icmp_akislar[anahtar].append(akis)

        for (kaynak, hedef), akis_listesi in icmp_akislar.items():
            toplam_icmp = sum(a.paket_sayisi for a in akis_listesi)
            if toplam_icmp >= self.sabitler.icmp_paket_esigi:
                guven = min(100.0, (toplam_icmp / self.sabitler.icmp_paket_esigi) * 60)
                kanit = {
                    "icmp_paketleri": toplam_icmp,
                    "esik": self.sabitler.icmp_paket_esigi,
                }
                bulgu = TehditBulgusu(
                    tespit_turu="icmp_anomalisi",
                    baslik="Olası ICMP Trafik Anomalisi",
                    aciklama=f"Host {kaynak}, {hedef} adresine {toplam_icmp} ICMP paketi gonderdi.",
                    seviye=TehditSeviyesi.ORTA,
                    puan=int(guven),
                    guven=round(guven, 1),
                    kaynak=kaynak,
                    hedef=hedef,
                    kanit=kanit,
                    onerilen_aksiyon="ICMP trafik desenini gozden gecirin. ICMP flood'lar genellikle keşif veya DoS girişimlerinde kullanilir.",
                )
                bulgular.append(bulgu)

        return bulgular
