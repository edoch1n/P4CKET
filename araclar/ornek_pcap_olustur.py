#!/usr/bin/env python3
"""Ornek PCAP dosyasi olusturucu."""

import random
import sys
import warnings
from contextlib import redirect_stderr
from datetime import datetime, timedelta
from io import StringIO

warnings.filterwarnings("ignore", message=".*libpcap.*")
warnings.filterwarnings("ignore", message=".*getmacbyip.*")

_stderr = StringIO()
with redirect_stderr(_stderr):
    from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap, conf

conf.verb = 0
conf.use_pcap = False


def ornek_pcap_olustur(cikti_yolu: str = "ornekler/ornek_trafik.pcap") -> None:
    random.seed(42)
    base_time = datetime(2024, 1, 1, 10, 0, 0)
    paketler = []

    benign_hosts = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
    tarayici = "192.168.1.100"
    hedef = "192.168.1.20"
    dns_kullanicisi = "192.168.1.30"
    beacon_kaynak = "192.168.1.40"
    beacon_hedef = "192.168.1.50"

    for i in range(200):
        kaynak = random.choice(benign_hosts)
        hedef_ip = random.choice(["8.8.8.8", "1.1.1.1", "192.168.1.1"])
        ts = (base_time + timedelta(seconds=i * random.uniform(0.1, 0.5))).timestamp()
        pkt = IP(src=kaynak, dst=hedef_ip) / TCP(
            sport=random.randint(1024, 65535), dport=443, flags="PA"
        )
        pkt.time = ts
        paketler.append(pkt)

    for port in range(1, 25):
        ts = (base_time + timedelta(seconds=port)).timestamp()
        pkt = IP(src=tarayici, dst=hedef) / TCP(
            sport=random.randint(1024, 65535), dport=port, flags="S"
        )
        pkt.time = ts
        paketler.append(pkt)

    for i in range(150):
        ts = (base_time + timedelta(seconds=30 + i * 0.2)).timestamp()
        pkt = IP(src=dns_kullanicisi, dst="8.8.8.8") / UDP(
            sport=12345, dport=53
        ) / DNS(rd=1, qd=DNSQR(qname=f"random{i}.example.com"))
        pkt.time = ts
        paketler.append(pkt)

    for i in range(20):
        ts = (base_time + timedelta(seconds=60 + i * 5)).timestamp()
        pkt = IP(src=beacon_kaynak, dst=beacon_hedef) / TCP(
            sport=4444, dport=80, flags="PA"
        )
        pkt.time = ts
        paketler.append(pkt)

    stderr_hata = StringIO()
    with redirect_stderr(stderr_hata):
        wrpcap(cikti_yolu, paketler)
    print(f"Ornek PCAP yazildi: {cikti_yolu} ({len(paketler)} paket)")


if __name__ == "__main__":
    ornek_pcap_olustur()
