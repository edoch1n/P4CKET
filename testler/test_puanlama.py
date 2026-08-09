"""Puanlama testleri."""

import pytest

from p4cket.yardimci.sabitler import PuanlamaSabitleri
from p4cket.modeller import TehditSeviyesi
from p4cket.motor.puanlama import seviye_hesapla


def test_seviye_dusuk():
    assert seviye_hesapla(0) == TehditSeviyesi.DUSUK
    assert seviye_hesapla(39) == TehditSeviyesi.DUSUK


def test_seviye_orta():
    assert seviye_hesapla(40) == TehditSeviyesi.ORTA
    assert seviye_hesapla(69) == TehditSeviyesi.ORTA


def test_seviye_yuksek():
    assert seviye_hesapla(70) == TehditSeviyesi.YUKSEK
    assert seviye_hesapla(89) == TehditSeviyesi.YUKSEK


def test_seviye_kritik():
    assert seviye_hesapla(90) == TehditSeviyesi.KRITIK
    assert seviye_hesapla(100) == TehditSeviyesi.KRITIK


def test_ozel_ayarlar():
    sabitler = PuanlamaSabitleri(dusuk_ust=20, orta_ust=50, yuksek_ust=80, kritik_alt=90)
    assert seviye_hesapla(15, sabitler) == TehditSeviyesi.DUSUK
    assert seviye_hesapla(45, sabitler) == TehditSeviyesi.ORTA
    assert seviye_hesapla(70, sabitler) == TehditSeviyesi.YUKSEK
    assert seviye_hesapla(95, sabitler) == TehditSeviyesi.KRITIK
