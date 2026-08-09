"""DNS anomali testleri."""

import pytest

from p4cket.yardimci.sabitler import DnsAnomalisiSabitleri
from p4cket.tespit.dns_anomalisi import DnsAnomalisiTespit
from p4cket.modeller import PaketKaydi


def _dns_paketi_olustur(kaynak, sorgu, nxdomain=False):
    cevap = "NXDOMAIN" if nxdomain else "192.168.1.1"
    return PaketKaydi(
        zaman_damgasi=0.0,
        kaynak_ip=kaynak,
        hedef_ip="8.8.8.8",
        protokol="UDP",
        kaynak_port=12345,
        hedef_port=53,
        dns_sorgusu=sorgu,
        dns_cevabi=cevap,
    )


def test_esik_altinda_dns_yok():
    sabitler = DnsAnomalisiSabitleri(sorgu_esigi=1000)
    tespit = DnsAnomalisiTespit(sabitler)
    paketler = [_dns_paketi_olustur("192.168.1.1", f"host{i}.com") for i in range(10)]
    bulgular = tespit.calistir(paketler)
    assert len(bulgular) == 0


def test_yuksek_sorgu_sayisi_tespit_edildi():
    sabitler = DnsAnomalisiSabitleri(sorgu_esigi=10)
    tespit = DnsAnomalisiTespit(sabitler)
    paketler = [_dns_paketi_olustur("192.168.1.1", f"host{i}.com") for i in range(20)]
    bulgular = tespit.calistir(paketler)
    assert len(bulgular) >= 1
    basliklar = [b.baslik for b in bulgular]
    assert any("Süpheli DNS" in b for b in basliklar)


def test_nxdomain_orani_tespit_edildi():
    sabitler = DnsAnomalisiSabitleri(sorgu_esigi=5, nxdomain_orani_esigi=0.4)
    tespit = DnsAnomalisiTespit(sabitler)
    paketler = [_dns_paketi_olustur("192.168.1.1", f"host{i}.com", nxdomain=True) for i in range(10)]
    bulgular = tespit.calistir(paketler)
    assert len(bulgular) >= 1
    basliklar = [b.baslik for b in bulgular]
    assert any("NXDOMAIN" in b for b in basliklar)


def test_uzun_sorgu_tespit_edildi():
    sabitler = DnsAnomalisiSabitleri(maks_sorgu_uzunlugu=20)
    tespit = DnsAnomalisiTespit(sabitler)
    uzun_sorgu = "a" * 50 + ".com"
    paketler = [_dns_paketi_olustur("192.168.1.1", uzun_sorgu) for _ in range(5)]
    bulgular = tespit.calistir(paketler)
    assert len(bulgular) >= 1
    basliklar = [b.baslik for b in bulgular]
    assert any("Uzun" in b for b in basliklar)
