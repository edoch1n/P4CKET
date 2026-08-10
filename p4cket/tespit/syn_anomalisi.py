import logging
from collections import defaultdict
from typing import Optional

from p4cket.modeller import AgAkisi, TehditBulgusu, TehditSeviyesi
from p4cket.yardimci.sabitler import TrafikAnomalisiSabitleri

logger = logging.getLogger(__name__)


class SynAnomalisiTespit:
    def __init__(self, sabitler: Optional[TrafikAnomalisiSabitleri] = None):
        self.sabitler = sabitler or TrafikAnomalisiSabitleri()

    def calistir(self, akislar: list[AgAkisi]) -> list[TehditBulgusu]:
        bulgular: list[TehditBulgusu] = []
        syn_akislar: dict[tuple[str, str], list[AgAkisi]] = defaultdict(list)

        for akis in akislar:
            if akis.protokol == "TCP" and akis.syn_sayisi > 0:
                anahtar = (akis.kaynak_ip, akis.hedef_ip)
                syn_akislar[anahtar].append(akis)

        for (kaynak, hedef), akis_listesi in syn_akislar.items():
            toplam_syn = sum(a.syn_sayisi for a in akis_listesi)
            if toplam_syn >= self.sabitler.syn_paket_esigi:
                guven = min(100.0, (toplam_syn / self.sabitler.syn_paket_esigi) * 60)
                kanit = {
                    "syn_paketleri": toplam_syn,
                    "syn_ack_sayisi": sum(a.syn_ack_sayisi for a in akis_listesi),
                    "esik": self.sabitler.syn_paket_esigi,
                }
                bulgu = TehditBulgusu(
                    tespit_turu="syn_anomalisi",
                    baslik="Olası SYN Trafik Anomalisi",
                    aciklama=f"Host {kaynak}, {hedef} adresine {toplam_syn} SYN paketi gonderdi.",
                    seviye=TehditSeviyesi.YUKSEK,
                    puan=int(guven),
                    guven=round(guven, 1),
                    kaynak=kaynak,
                    hedef=hedef,
                    kanit=kanit,
                    onerilen_aksiyon="Kaynak hostu izleyin. SYN paketlerini ag kenarinda sinirlandirmayi degerlendirin.",
                )
                bulgular.append(bulgu)

        return bulgular
