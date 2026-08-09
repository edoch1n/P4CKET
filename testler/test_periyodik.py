"""Periyodik iletisim testleri."""

import statistics

import pytest

from p4cket.yardimci.sabitler import PeriyodikIletisimSabitleri
from p4cket.tespit.periyodik_iletisim import PeriyodikIletisimTespit, _araliklari_hesapla, _degisim_katsayisi
from p4cket.modeller import AgAkisi


def _akıs_olustur(kaynak, hedef, zaman_damgalari):
    return AgAkisi(
        akis_id=f"{kaynak}:0-{hedef}:0-TCP",
        kaynak_ip=kaynak,
        hedef_ip=hedef,
        kaynak_port=None,
        hedef_port=None,
        protokol="TCP",
        zaman_damgalari=zaman_damgalari,
    )


def test_araliklari_hesapla():
    assert _araliklari_hesapla([1.0, 2.0, 4.0]) == [1.0, 2.0]


def test_degisim_katsayisi():
    assert _degisim_katsayisi([1.0, 1.0, 1.0]) == 0.0


def test_gözlem_altinda_periyodik_yok():
    sabitler = PeriyodikIletisimSabitleri(min_gözlem=10)
    tespit = PeriyodikIletisimTespit(sabitler)
    akislar = [_akıs_olustur("192.168.1.1", "192.168.1.2", [1.0, 2.0, 3.0])]
    bulgular = tespit.calistir(akislar)
    assert len(bulgular) == 0


def test_periyodik_tespit_edildi():
    sabitler = PeriyodikIletisimSabitleri(min_gözlem=5, duzenlilik_esigi=0.7)
    zaman_damgalari = [0.0, 10.0, 20.0, 30.0, 40.0, 50.0]
    akislar = [_akıs_olustur("192.168.1.1", "192.168.1.2", zaman_damgalari)]
    tespit = PeriyodikIletisimTespit(sabitler)
    bulgular = tespit.calistir(akislar)
    assert len(bulgular) == 1
    assert bulgular[0].tespit_turu == "periyodik_iletisim"
    assert "Periyodik" in bulgular[0].baslik


def test_duzensiz_tespit_edilmez():
    sabitler = PeriyodikIletisimSabitleri(min_gözlem=5, duzenlilik_esigi=0.5)
    zaman_damgalari = [0.0, 1.0, 15.0, 16.0, 100.0]
    akislar = [_akıs_olustur("192.168.1.1", "192.168.1.2", zaman_damgalari)]
    tespit = PeriyodikIletisimTespit(sabitler)
    bulgular = tespit.calistir(akislar)
    assert len(bulgular) == 0
