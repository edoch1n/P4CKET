"""JSON rapor uretici."""

import json
from datetime import datetime
from typing import Optional

from p4cket.modeller import AnalizOzeti, TehditBulgusu


def json_rapor_olustur(ozet: AnalizOzeti, cikti_yolu: str) -> None:
    rapor = {
        "metadata": {
            "arac": "P4CKET",
            "surum": "1.0.0",
            "aciklama": "PCAP Ag Trafigi Analiz ve Tehdit Tespit Sistemi",
        },
        "analiz_zamani": ozet.analiz_zamani,
        "pcap_bilgisi": {
            "dosya": ozet.pcap_dosya,
            "toplam_paket": ozet.toplam_paket,
            "benzersiz_host": ozet.benzersiz_host,
            "tcp_akislari": ozet.tcp_akislari,
            "udp_akislari": ozet.udp_akislari,
            "icmp_paketleri": ozet.icmp_paketleri,
            "dns_paketleri": ozet.dns_paketleri,
        },
        "istatistikler": {
            "toplam_bulgu": len(ozet.bulgular),
            "bulgular_seviyeye_gore": _seviyeye_gore_say(ozet.bulgular),
        },
        "bulgular": [
            {
                "tespit_turu": b.tespit_turu,
                "baslik": b.baslik,
                "aciklama": b.aciklama,
                "seviye": b.seviye.value,
                "puan": b.puan,
                "guven": b.guven,
                "kaynak": b.kaynak,
                "hedef": b.hedef,
                "kanit": b.kanit,
                "zaman": b.zaman,
                "onerilen_aksiyon": b.onerilen_aksiyon,
            }
            for b in ozet.bulgular
        ],
        "genel_risk": {
            "puan": ozet.genel_risk_puani,
            "tehdit_seviyesi": ozet.tehdit_seviyesi.value,
        },
        "oneriler": ozet.oneriler,
    }

    with open(cikti_yolu, "w", encoding="utf-8") as f:
        json.dump(rapor, f, indent=2, ensure_ascii=False, default=str)


def _seviyeye_gore_say(bulgular: list[TehditBulgusu]) -> dict[str, int]:
    sayimlar: dict[str, int] = {}
    for b in bulgular:
        anahtar = b.seviye.value
        sayimlar[anahtar] = sayimlar.get(anahtar, 0) + 1
    return sayimlar
