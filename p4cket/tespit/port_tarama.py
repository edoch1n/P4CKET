"""Port tarama tespit motoru."""

import logging
from collections import defaultdict
from typing import Optional

from p4cket.modeller import AgAkisi, TehditBulgusu, TehditSeviyesi
from p4cket.yardimci.sabitler import PortTaramaSabitleri

logger = logging.getLogger(__name__)


class PortTaramaTespit:
    def __init__(self, sabitler: Optional[PortTaramaSabitleri] = None):
        self.sabitler = sabitler or PortTaramaSabitleri()

    def calistir(self, akislar: list[AgAkisi]) -> list[TehditBulgusu]:
        bulgular: list[TehditBulgusu] = []

        kaynak_hedef_port: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
        kaynak_hedef_host: dict[str, set[str]] = defaultdict(set)

        for akis in akislar:
            if akis.protokol not in ("TCP", "UDP"):
                continue
            kaynak = akis.kaynak_ip
            hedef = akis.hedef_ip
            port = akis.hedef_port
            if port is not None:
                kaynak_hedef_port[kaynak][hedef].add(port)
            kaynak_hedef_host[kaynak].add(hedef)

        for kaynak_ip, hedef_port in kaynak_hedef_port.items():
            benzersiz_hedef = len(hedef_port)
            toplam_benzersiz_port = sum(len(portlar) for portlar in hedef_port.values())

            if toplam_benzersiz_port >= self.sabitler.port_esigi:
                guven = min(100.0, (toplam_benzersiz_port / self.sabitler.port_esigi) * 50)
                seviye = TehditSeviyesi.YUKSEK if toplam_benzersiz_port >= self.sabitler.port_esigi * 2 else TehditSeviyesi.ORTA
                hedefler = ", ".join(sorted(hedef_port.keys())[:5])
                if len(hedef_port) > 5:
                    hedefler += f" (+{len(hedef_port) - 5} daha)"

                kanit = {
                    "toplam_benzersiz_port": toplam_benzersiz_port,
                    "benzersiz_hedef": benzersiz_hedef,
                    "port_esigi": self.sabitler.port_esigi,
                    "hedefler": hedefler,
                }

                bulgu = TehditBulgusu(
                    tespit_turu="port_tarama",
                    baslik="Olası Port Tarama",
                    aciklama=f"Kaynak {kaynak_ip}, {toplam_benzersiz_port} farkli porta {benzersiz_hedef} hedef(te) baglanmaya calisti.",
                    seviye=seviye,
                    puan=int(guven),
                    guven=round(guven, 1),
                    kaynak=kaynak_ip,
                    hedef=hedefler,
                    kanit=kanit,
                    onerilen_aksiyon="Kaynak sistemi inceleyin. Tarama yetkisini dogrulayin.",
                )
                bulgular.append(bulgu)
                logger.debug("Port taramasi tespit edildi: %s", kaynak_ip)

        return bulgular
