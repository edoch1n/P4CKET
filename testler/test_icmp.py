"""ICMP anomalisi testleri."""

import pytest

from p4cket.yardimci.sabitler import TrafikAnomalisiSabitleri
from p4cket.tespit.icmp_anomalisi import IcmpAnomalisiTespit
from p4cket.modeller import AgAkisi


def _akıs_olustur(kaynak, hedef, paket_sayisi=0, proto="ICMP"):
    return AgAkisi(
        akis_id=f"{kaynak}:0-{hedef}:0-{proto}",
        kaynak_ip=kaynak,
        hedef_ip=hedef,
        kaynak_port=None,
        hedef_port=None,
        protokol=proto,
        paket_sayisi=paket_sayisi,
    )


def test_esik_altinda_icmp_yok():
    sabitler = TrafikAnomalisiSabitleri(icmp_paket_esigi=1000)
    tespit = IcmpAnomalisiTespit(sabitler)
    akislar = [_akıs_olustur("192.168.1.1", "192.168.1.2", paket_sayisi=10)]
    bulgular = tespit.calistir(akislar)
    assert len(bulgular) == 0


def test_icmp_flood_tespit_edildi():
    sabitler = TrafikAnomalisiSabitleri(icmp_paket_esigi=50)
    tespit = IcmpAnomalisiTespit(sabitler)
    akislar = [_akıs_olustur("192.168.1.1", "192.168.1.2", paket_sayisi=100)]
    bulgular = tespit.calistir(akislar)
    assert len(bulgular) == 1
    assert "ICMP" in bulgular[0].baslik
