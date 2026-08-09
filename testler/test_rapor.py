"""Rapor testleri."""

import json
import os
import tempfile

from p4cket.modeller import AnalizOzeti, TehditBulgusu, TehditSeviyesi
from p4cket.rapor.json_rapor import json_rapor_olustur
from p4cket.rapor.txt_rapor import txt_rapor_olustur


def _ornek_ozet() -> AnalizOzeti:
    bulgu = TehditBulgusu(
        tespit_turu="port_tarama",
        baslik="Olası Port Tarama",
        aciklama="Test aciklama",
        seviye=TehditSeviyesi.YUKSEK,
        puan=85,
        guven=92.0,
        kaynak="192.168.1.1",
        hedef="192.168.1.2",
        kanit={"test": "deger"},
        onerilen_aksiyon="Test oneri",
    )
    return AnalizOzeti(
        pcap_dosya="test.pcap",
        analiz_zamani="2024-01-01T00:00:00",
        toplam_paket=100,
        benzersiz_host=5,
        tcp_akislari=50,
        udp_akislari=30,
        icmp_paketleri=10,
        dns_paketleri=10,
        bulgular=[bulgu],
        genel_risk_puani=85,
        tehdit_seviyesi=TehditSeviyesi.YUKSEK,
        oneriler=["Test oneri 1", "Test oneri 2"],
    )


def test_json_rapor_olustur():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        cikti_yolu = f.name
    try:
        ozet = _ornek_ozet()
        json_rapor_olustur(ozet, cikti_yolu)
        assert os.path.exists(cikti_yolu)
        with open(cikti_yolu, "r", encoding="utf-8") as f:
            veri = json.load(f)
        assert veri["genel_risk"]["puan"] == 85
        assert veri["genel_risk"]["tehdit_seviyesi"] == "YÜKSEK"
        assert len(veri["bulgular"]) == 1
    finally:
        os.unlink(cikti_yolu)


def test_txt_rapor_olustur():
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        cikti_yolu = f.name
    try:
        ozet = _ornek_ozet()
        txt_rapor_olustur(ozet, cikti_yolu)
        assert os.path.exists(cikti_yolu)
        with open(cikti_yolu, "r", encoding="utf-8") as f:
            icerik = f.read()
        assert "P4CKET ANALIZ RAPORU" in icerik
        assert "Olası Port Tarama" in icerik
    finally:
        os.unlink(cikti_yolu)
