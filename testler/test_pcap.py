"""PCAP ayrıştırıcı testleri."""

import os
import tempfile

import pytest
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap

from p4cket.modeller import PaketKaydi
from p4cket.motor.pcap_ayristirici import pcap_ayristir, _paket_ayristir


def _pcap_olustur(paketler, dosya_yolu):
    wrpcap(dosya_yolu, paketler)


def test_bos_pcap():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        dosya_yolu = f.name
    try:
        wrpcap(dosya_yolu, [])
        paketler, toplam, atlanan = pcap_ayristir(dosya_yolu)
        assert toplam == 0
        assert len(paketler) == 0
    finally:
        os.unlink(dosya_yolu)


def test_tcp_paketi_ayristirma():
    from scapy.all import Ether
    pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="S")
    kayit = _paket_ayristir(pkt)
    assert kayit is not None
    assert kayit.kaynak_ip == "192.168.1.1"
    assert kayit.hedef_ip == "192.168.1.2"
    assert kayit.kaynak_port == 1234
    assert kayit.hedef_port == 80
    assert kayit.protokol == "TCP"
    assert kayit.tcp_bayraklari == "S"


def test_udp_paketi_ayristirma():
    from scapy.all import Ether
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=12345)
    kayit = _paket_ayristir(pkt)
    assert kayit is not None
    assert kayit.protokol == "UDP"
    assert kayit.kaynak_port == 53
    assert kayit.hedef_port == 12345


def test_icmp_paketi_ayristirma():
    from scapy.all import Ether
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, code=0)
    kayit = _paket_ayristir(pkt)
    assert kayit is not None
    assert kayit.protokol == "ICMP"
    assert kayit.icmp_tipi == 8
    assert kayit.icmp_kodu == 0


def test_ip_olmayan_paket():
    from scapy.all import Ether, ARP
    pkt = Ether() / ARP()
    kayit = _paket_ayristir(pkt)
    assert kayit is None


def test_bozuk_paket_toleransi():
    from scapy.all import Ether
    pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="S")
    kayit = _paket_ayristir(pkt)
    assert kayit is not None
