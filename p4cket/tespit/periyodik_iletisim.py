import logging
import statistics
from collections import defaultdict
from typing import Optional

from p4cket.modeller import AgAkisi, TehditBulgusu, TehditSeviyesi
from p4cket.yardimci.sabitler import PeriyodikIletisimSabitleri

logger = logging.getLogger(__name__)


def _araliklari_hesapla(zaman_damgalari: list[float]) -> list[float]:
    if len(zaman_damgalari) < 2:
        return []
    return [t2 - t1 for t1, t2 in zip(zaman_damgalari, zaman_damgalari[1:])]


def _degisim_katsayisi(araliklar: list[float]) -> float:
    if not araliklar:
        return 1.0
    ortalama = statistics.mean(araliklar)
    if ortalama == 0:
        return 1.0
    std_sapma = statistics.stdev(araliklar) if len(araliklar) > 1 else 0.0
    return std_sapma / ortalama


class PeriyodikIletisimTespit:
    def __init__(self, sabitler: Optional[PeriyodikIletisimSabitleri] = None):
        self.sabitler = sabitler or PeriyodikIletisimSabitleri()

    def calistir(self, akislar: list[AgAkisi]) -> list[TehditBulgusu]:
        bulgular: list[TehditBulgusu] = []
        kaynak_hedef_akis: dict[tuple[str, str], list[AgAkisi]] = defaultdict(list)

        for akis in akislar:
            anahtar = (akis.kaynak_ip, akis.hedef_ip)
            kaynak_hedef_akis[anahtar].append(akis)

        for (kaynak, hedef), akis_listesi in kaynak_hedef_akis.items():
            zaman_damgalari: list[float] = []
            for a in akis_listesi:
                zaman_damgalari.extend(a.zaman_damgalari)
            zaman_damgalari = sorted(set(zaman_damgalari))

            if len(zaman_damgalari) < self.sabitler.min_gözlem:
                continue

            araliklar = _araliklari_hesapla(zaman_damgalari)
            if not araliklar:
                continue

            cv = _degisim_katsayisi(araliklar)
            ortalama_aralik = statistics.mean(araliklar)

            if cv <= (1.0 - self.sabitler.duzenlilik_esigi):
                guven = min(100.0, (1.0 - cv) * 80 + (len(zaman_damgalari) / self.sabitler.min_gözlem) * 20)
                guven = round(guven, 1)
                seviye = TehditSeviyesi.YUKSEK if guven >= 70 else TehditSeviyesi.ORTA

                kanit = {
                    "gozlem_sayisi": len(zaman_damgalari),
                    "ortalama_aralik_saniye": round(ortalama_aralik, 2),
                    "cv": round(cv, 4),
                    "duzenlilik_puani": round(1.0 - cv, 4),
                }

                bulgu = TehditBulgusu(
                    tespit_turu="periyodik_iletisim",
                    baslik="Olası Periyodik Iletisim",
                    aciklama=f"Host {kaynak}, {hedef} adresine yaklasik olarak periyodik baglanıyor (aralik ~{ortalama_aralik:.1f}s).",
                    seviye=seviye,
                    puan=int(guven),
                    guven=guven,
                    kaynak=kaynak,
                    hedef=hedef,
                    kanit=kanit,
                    onerilen_aksiyon="Periyodik baglantilari inceleyin. Olası C2 beaconing veya legit heartbeat olabilir.",
                )
                bulgular.append(bulgu)
                logger.debug("Periyodik iletisim tespit edildi: %s -> %s", kaynak, hedef)

        return bulgular
