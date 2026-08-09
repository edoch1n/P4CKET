"""SYN anomalisi testleri."""

import pytest

from p4cket.yardimci.sabitler import TrafikAnomalisiSabitleri
from p4cket.tespit.syn_anomalisi import SynAnomalisiTespit
from p4cket.modeller import AgAkisi


def _akıs_olustur(kaynak, hedef, syn_sayisi=0, proto="TCP"):
    return AgAkisi(
        akis_id=f"{kaynak}:0-{hedef}:0-{proto}",
        kaynak_ip=kaynak,
        hedef_ip=hedef,
        kaynak_port=None,
        hedef_port=None,
        protokol=proto,
        syn_sayisi=syn_sayisi,
        paket_sayisi=syn_sayisi,
    )


def test_esik_altinda_syn_yok():
    sabitler = TrafikAnomalisiSabitleri(syn_paket_esigi=1000)
    tespit = SynAnomalisiTespit(sabitler)
    akislar = [_akıs_olustur("192.168.1.1", "192.168.1.2", syn_sayisi=10) for _ in range(2)]
    bulgular = tespit.calistir(akislar)
    assert len(bulgular) == 0


def test_syn_flood_tespit_edildi():
    sabitler = TrafikAnomalisiSabitleri(syn_paket_esigi=100)
    tespit = SynAnomalisiTespit(sabitler)
    akislar = [_akıs_olustur("192.168.1.1", "192.168.1.2", syn_sayisi=200)]
    bulgular = tespit.calistir(akislar)
    assert len(bulgular) == 1
    assert bulgular[0].tespit_turu == "syn_anomalisi"
    assert "SYN" in bulgular[0].baslik
