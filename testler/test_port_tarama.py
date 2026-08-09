"""Port tarama tespit testleri."""

import pytest

from p4cket.yardimci.sabitler import PortTaramaSabitleri
from p4cket.tespit.port_tarama import PortTaramaTespit
from p4cket.modeller import AgAkisi


def _akıs_olustur(kaynak, hedef, spor=None, hport=None, proto="TCP"):
    return AgAkisi(
        akis_id=f"{kaynak}:{spor}-{hedef}:{hport}-{proto}",
        kaynak_ip=kaynak,
        hedef_ip=hedef,
        kaynak_port=spor,
        hedef_port=hport,
        protokol=proto,
    )


def test_esik_altinda_tarama_yok():
    sabitler = PortTaramaSabitleri(port_esigi=10)
    tespit = PortTaramaTespit(sabitler)
    akislar = [_akıs_olustur("192.168.1.1", "192.168.1.2", hport=80) for _ in range(3)]
    bulgular = tespit.calistir(akislar)
    assert len(bulgular) == 0


def test_port_taramasi_tespit_edildi():
    sabitler = PortTaramaSabitleri(port_esigi=5)
    tespit = PortTaramaTespit(sabitler)
    akislar = [_akıs_olustur("192.168.1.1", "192.168.1.2", hport=p) for p in range(1, 11)]
    bulgular = tespit.calistir(akislar)
    assert len(bulgular) == 1
    assert bulgular[0].tespit_turu == "port_tarama"
    assert bulgular[0].kaynak == "192.168.1.1"


def test_udp_taramasi_tespit_edildi():
    sabitler = PortTaramaSabitleri(port_esigi=5)
    tespit = PortTaramaTespit(sabitler)
    akislar = [_akıs_olustur("10.0.0.1", "10.0.0.2", hport=p, proto="UDP") for p in range(1, 11)]
    bulgular = tespit.calistir(akislar)
    assert len(bulgular) == 1


def test_guven_puani_port_sayisiyla_artar():
    sabitler = PortTaramaSabitleri(port_esigi=5)
    tespit = PortTaramaTespit(sabitler)
    akislar = [_akıs_olustur("192.168.1.1", "192.168.1.2", hport=p) for p in range(1, 21)]
    bulgular = tespit.calistir(akislar)
    assert len(bulgular) == 1
    assert bulgular[0].puan > 50
