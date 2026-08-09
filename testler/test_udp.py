"""UDP anomalisi testleri."""

import pytest

from p4cket.yardimci.sabitler import TrafikAnomalisiSabitleri
from p4cket.tespit.udp_anomalisi import UdpAnomalisiTespit
from p4cket.modeller import AgAkisi


def _akıs_olustur(kaynak, hedef, paket_sayisi=0, proto="UDP"):
    return AgAkisi(
        akis_id=f"{kaynak}:0-{hedef}:0-{proto}",
        kaynak_ip=kaynak,
        hedef_ip=hedef,
        kaynak_port=None,
        hedef_port=None,
        protokol=proto,
        paket_sayisi=paket_sayisi,
    )


def test_esik_altinda_udp_yok():
    sabitler = TrafikAnomalisiSabitleri(udp_paket_esigi=1000)
    tespit = UdpAnomalisiTespit(sabitler)
    akislar = [_akıs_olustur("192.168.1.1", "192.168.1.2", paket_sayisi=10)]
    bulgular = tespit.calistir(akislar)
    assert len(bulgular) == 0


def test_udp_flood_tespit_edildi():
    sabitler = TrafikAnomalisiSabitleri(udp_paket_esigi=100)
    tespit = UdpAnomalisiTespit(sabitler)
    akislar = [_akıs_olustur("192.168.1.1", "192.168.1.2", paket_sayisi=500)]
    bulgular = tespit.calistir(akislar)
    assert len(bulgular) == 1
    assert "UDP" in bulgular[0].baslik
