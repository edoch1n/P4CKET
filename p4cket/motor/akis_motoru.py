import logging
from collections import defaultdict
from typing import Optional

from p4cket.modeller import AgAkisi, PaketKaydi

logger = logging.getLogger(__name__)


def _akis_id_olustur(kaynak_ip: str, hedef_ip: str, kaynak_port: Optional[int], hedef_port: Optional[int], protokol: str) -> str:
    return f"{kaynak_ip}:{kaynak_port}-{hedef_ip}:{hedef_port}-{protokol}"


def akislari_olustur(paketler: list[PaketKaydi]) -> list[AgAkisi]:
    akislar: dict[str, AgAkisi] = {}

    for pkt in paketler:
        akis_id = _akis_id_olustur(
            pkt.kaynak_ip, pkt.hedef_ip, pkt.kaynak_port, pkt.hedef_port, pkt.protokol
        )

        if akis_id not in akislar:
            akislar[akis_id] = AgAkisi(
                akis_id=akis_id,
                kaynak_ip=pkt.kaynak_ip,
                hedef_ip=pkt.hedef_ip,
                kaynak_port=pkt.kaynak_port,
                hedef_port=pkt.hedef_port,
                protokol=pkt.protokol,
                ilk_gorulme=pkt.zaman_damgasi,
                son_gorulme=pkt.zaman_damgasi,
            )

        akis = akislar[akis_id]
        akis.paket_sayisi += 1
        akis.bayt_sayisi += pkt.uzunluk
        akis.zaman_damgalari.append(pkt.zaman_damgasi)
        akis.son_gorulme = max(akis.son_gorulme, pkt.zaman_damgasi)
        akis.ilk_gorulme = min(akis.ilk_gorulme, pkt.zaman_damgasi)

        if pkt.tcp_bayraklari:
            akis.tcp_bayraklari.append(pkt.tcp_bayraklari)
            bayraklar = pkt.tcp_bayraklari.upper()
            if "S" in bayraklar and "A" not in bayraklar:
                akis.syn_sayisi += 1
                akis.baglanti_denemeleri += 1
            elif "S" in bayraklar and "A" in bayraklar:
                akis.syn_ack_sayisi += 1
            if "F" in bayraklar:
                akis.fin_sayisi += 1
            if "R" in bayraklar:
                akis.rst_sayisi += 1

    sonuc = list(akislar.values())
    logger.info("%d akis olusturuldu (%d paket)", len(sonuc), len(paketler))
    return sonuc
