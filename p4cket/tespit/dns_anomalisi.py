import logging
import math
from collections import defaultdict
from typing import Optional

from p4cket.modeller import PaketKaydi, TehditBulgusu, TehditSeviyesi
from p4cket.yardimci.sabitler import DnsAnomalisiSabitleri

logger = logging.getLogger(__name__)


def _shannon_entropi(veri: str) -> float:
    if not veri:
        return 0.0
    entropi = 0.0
    for karakter in set(veri):
        p_x = veri.count(karakter) / len(veri)
        entropi -= p_x * math.log2(p_x)
    return entropi


class DnsAnomalisiTespit:
    def __init__(self, sabitler: Optional[DnsAnomalisiSabitleri] = None):
        self.sabitler = sabitler or DnsAnomalisiSabitleri()

    def calistir(self, paketler: list[PaketKaydi]) -> list[TehditBulgusu]:
        bulgular: list[TehditBulgusu] = []

        kaynak_sorgular: dict[str, list[str]] = defaultdict(list)
        kaynak_domain: dict[str, set[str]] = defaultdict(set)
        kaynak_nxdomain: dict[str, int] = defaultdict(int)
        kaynak_toplam: dict[str, int] = defaultdict(int)

        for pkt in paketler:
            if pkt.dns_sorgusu:
                kaynak = pkt.kaynak_ip
                kaynak_sorgular[kaynak].append(pkt.dns_sorgusu)
                kaynak_domain[kaynak].add(pkt.dns_sorgusu)
                kaynak_toplam[kaynak] += 1

            if pkt.dns_cevabi and "NXDOMAIN" in (pkt.dns_cevabi or "").upper():
                kaynak_nxdomain[pkt.kaynak_ip] += 1

        for kaynak_ip, sorgular in kaynak_sorgular.items():
            toplam = kaynak_toplam[kaynak_ip]
            benzersiz = len(kaynak_domain[kaynak_ip])
            nxdomain = kaynak_nxdomain.get(kaynak_ip, 0)

            if toplam >= self.sabitler.sorgu_esigi:
                guven = min(100.0, (toplam / self.sabitler.sorgu_esigi) * 60)
                kanit = {
                    "sorgu_sayisi": toplam,
                    "benzersiz_domain": benzersiz,
                    "esik": self.sabitler.sorgu_esigi,
                }
                bulgu = TehditBulgusu(
                    tespit_turu="dns_anomalisi",
                    baslik="Süpheli DNS Trafigi",
                    aciklama=f"Host {kaynak_ip}, {toplam} DNS sorgusu yapti ({benzersiz} benzersiz domain).",
                    seviye=TehditSeviyesi.ORTA,
                    puan=int(guven),
                    guven=round(guven, 1),
                    kaynak=kaynak_ip,
                    kanit=kanit,
                    onerilen_aksiyon="DNS sorgularini gozden gecirin. Yuksek sorgu hacmi veri sizintisi veya C2 iletisimi olabilir.",
                )
                bulgular.append(bulgu)

            if benzersiz >= self.sabitler.benzersiz_domain_esigi:
                guven = min(100.0, (benzersiz / self.sabitler.benzersiz_domain_esigi) * 60)
                kanit = {
                    "benzersiz_domain": benzersiz,
                    "esik": self.sabitler.benzersiz_domain_esigi,
                }
                bulgu = TehditBulgusu(
                    tespit_turu="dns_anomalisi",
                    baslik="Yuksek Domain Cesitliligi",
                    aciklama=f"Host {kaynak_ip}, {benzersiz} benzersiz domain'i sorguladi.",
                    seviye=TehditSeviyesi.ORTA,
                    puan=int(guven),
                    guven=round(guven, 1),
                    kaynak=kaynak_ip,
                    kanit=kanit,
                    onerilen_aksiyon="Yuksek domain cesitliligi DNS tunelleme veya keşif olabilir.",
                )
                bulgular.append(bulgu)

            if toplam > 0 and nxdomain / toplam >= self.sabitler.nxdomain_orani_esigi:
                guven = min(100.0, (nxdomain / toplam) * 100)
                kanit = {
                    "nxdomain_sayisi": nxdomain,
                    "toplam_sorgu": toplam,
                    "nxdomain_orani": round(nxdomain / toplam, 2),
                }
                bulgu = TehditBulgusu(
                    tespit_turu="dns_anomalisi",
                    baslik="Asiri NXDOMAIN Yaniti",
                    aciklama=f"Host {kaynak_ip}, {toplam} sorgudan {nxdomain} tanesi NXDOMAIN yaniti aldi.",
                    seviye=TehditSeviyesi.ORTA,
                    puan=int(guven),
                    guven=round(guven, 1),
                    kaynak=kaynak_ip,
                    kanit=kanit,
                    onerilen_aksiyon="Yuksek NXDOMAIN orani DNS keşif veya tunelleme girisimlerini gosterebilir.",
                )
                bulgular.append(bulgu)

            uzun_sorgular = [s for s in sorgular if len(s) > self.sabitler.maks_sorgu_uzunlugu]
            if uzun_sorgular:
                ornek = uzun_sorgular[0]
                guven = min(100.0, (len(ornek) / self.sabitler.maks_sorgu_uzunlugu) * 70)
                kanit = {
                    "sorgu_sayisi": len(uzun_sorgular),
                    "ornek_uzunluk": len(ornek),
                    "ornek_sorgu": ornek[:100],
                }
                bulgu = TehditBulgusu(
                    tespit_turu="dns_anomalisi",
                    baslik="Anormal Uzun DNS Sorgu Adlari",
                    aciklama=f"Host {kaynak_ip}, {len(uzun_sorgular)} adet anormal uzun DNS sorgusu gonderdi.",
                    seviye=TehditSeviyesi.DUSUK,
                    puan=int(guven),
                    guven=round(guven, 1),
                    kaynak=kaynak_ip,
                    kanit=kanit,
                    onerilen_aksiyon="Uzun DNS sorgu adlari DNS tunelleme gostergesi olabilir.",
                )
                bulgular.append(bulgu)

            yuksek_entropi = [s for s in sorgular if _shannon_entropi(s) > self.sabitler.entropi_esigi]
            if yuksek_entropi:
                guven = min(100.0, (len(yuksek_entropi) / len(sorgular)) * 70)
                kanit = {
                    "yuksek_entropi_sayisi": len(yuksek_entropi),
                    "ornek": yuksek_entropi[0][:100],
                }
                bulgu = TehditBulgusu(
                    tespit_turu="dns_anomalisi",
                    baslik="Yuksek Sorgu Entropisi",
                    aciklama=f"Host {kaynak_ip}, {len(yuksek_entropi)} yuksek entropili DNS sorgusu yapti.",
                    seviye=TehditSeviyesi.DUSUK,
                    puan=int(guven),
                    guven=round(guven, 1),
                    kaynak=kaynak_ip,
                    kanit=kanit,
                    onerilen_aksiyon="Yuksek entropili DNS sorgulari veri sizintisi veya C2 iletisimi olabilir.",
                )
                bulgular.append(bulgu)

        return bulgular
