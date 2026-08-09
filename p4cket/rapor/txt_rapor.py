"""Metin (TXT) rapor uretici."""

from datetime import datetime
from typing import Optional

from p4cket.modeller import AnalizOzeti, TehditSeviyesi


def txt_rapor_olustur(ozet: AnalizOzeti, cikti_yolu: str) -> None:
    satirlar = [
        "=" * 60,
        " " * 20 + "P4CKET ANALIZ RAPORU",
        "=" * 60,
        "",
        "DOSYA:",
        ozet.pcap_dosya,
        "",
        "DURUM: TAMAMLANDI",
        "",
        "-" * 60,
        "",
        "GENEL RISK:",
        f"{ozet.genel_risk_puani} / 100",
        "",
        "TEHDIT SEVIYESI:",
        ozet.tehdit_seviyesi.value,
        "",
        "-" * 60,
        "",
        "TRAFIK OZETI",
        "",
        f"Toplam Paket       : {ozet.toplam_paket}",
        f"TCP Akisi          : {ozet.tcp_akislari}",
        f"UDP Akisi          : {ozet.udp_akislari}",
        f"ICMP Paketi        : {ozet.icmp_paketleri}",
        f"DNS Paketi         : {ozet.dns_paketleri}",
        f"Akis Sayisi        : {ozet.tcp_akislari + ozet.udp_akislari}",
        f"Kaynak Host        : {ozet.benzersiz_host}",
        "",
        "-" * 60,
        "",
        "TESPITLER",
        "",
    ]

    for bulgu in ozet.bulgular:
        satirlar.append(f"[{bulgu.seviye.value}] {bulgu.baslik}")
        satirlar.append(f"  Kaynak: {bulgu.kaynak}")
        if bulgu.hedef:
            satirlar.append(f"  Hedef: {bulgu.hedef}")
        satirlar.append(f"  Guven: %{bulgu.guven:.1f}")
        satirlar.append(f"  Puan: {bulgu.puan}")
        satirlar.append(f"  Aciklama: {bulgu.aciklama}")
        if bulgu.kanit:
            satirlar.append("  Kanit:")
            for k, v in bulgu.kanit.items():
                satirlar.append(f"    - {k}: {v}")
        satirlar.append("")

    satirlar.append("-" * 60)
    satirlar.append("")
    satirlar.append("ONERILER")
    satirlar.append("")
    for i, oneri in enumerate(ozet.oneriler, 1):
        satirlar.append(f"{i}. {oneri}")
    satirlar.append("")
    satirlar.append("=" * 60)
    satirlar.append(f"Rapor olusturulma: {datetime.now().isoformat()}")
    satirlar.append("=" * 60)

    with open(cikti_yolu, "w", encoding="utf-8") as f:
        f.write("\n".join(satirlar))
