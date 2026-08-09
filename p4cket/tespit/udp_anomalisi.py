"""UDP trafik anomalisi tespit motoru."""

import logging
from collections import defaultdict
from typing import Optional

from p4cket.modeller import AgAkisi, TehditBulgusu, TehditSeviyesi
from p4cket.yardimci.sabitler import TrafikAnomalisiSabitleri

logger = logging.getLogger(__name__)


class UdpAnomalisiTespit:
    def __init__(self, sabitler: Optional[TrafikAnomalisiSabitleri] = None):
        self.sabitler = sabitler or TrafikAnomalisiSabitleri()

    def calistir(self, akislar: list[AgAkisi]) -> list[TehditBulgusu]:
        bulgular: list[TehditBulgusu] = []
        udp_akislar: dict[tuple[str, str], list[AgAkisi]] = defaultdict(list)

        for akis in akislar:
            if akis.protokol == "UDP":
                anahtar = (akis.kaynak_ip, akis.hedef_ip)
                udp_akislar[anahtar].append(akis)

        for (kaynak, hedef), akis_listesi in udp_akislar.items():
            toplam_udp = sum(a.paket_sayisi for a in akis_listesi)
            if toplam_udp >= self.sabitler.udp_paket_esigi:
                guven = min(100.0, (toplam_udp / self.sabitler.udp_paket_esigi) * 50)
                kanit = {
                    "udp_paketleri": toplam_udp,
                    "esik": self.sabitler.udp_paket_esigi,
                }
                bulgu = TehditBulgusu(
                    tespit_turu="udp_anomalisi",
                    baslik="Olası UDP Trafik Anomalisi",
                    aciklama=f"Host {kaynak}, {hedef} adresine {toplam_udp} UDP paketi gonderdi.",
                    seviye=TehditSeviyesi.ORTA,
                    puan=int(guven),
                    guven=round(guven, 1),
                    kaynak=kaynak,
                    hedef=hedef,
                    kanit=kanit,
                    onerilen_aksiyon="UDP trafik desenini gozden gecirin. Yuksek UDP hacmi tarama veya uygulama katmani flood'u olabilir.",
                )
                bulgular.append(bulgu)

        return bulgular
