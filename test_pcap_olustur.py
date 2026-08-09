"""
P4CKET - Kapsamlı Sentetik Test PCAP Oluşturucu

Tamamen yapay trafik üretir. Gerçek hedeflere paket göndermez.
P4CKET'in aşağıdaki tespit motorlarını test etmek için tasarlanmıştır:
- Port tarama
- SYN anomalisi
- ICMP anomalisi
- UDP anomalisi
- DNS anomalisi
- Periyodik iletişim

Kullanım:
    python test_pcap_olustur.py

Çıktı:
    test_pcap/p4cket_test_trafik.pcap
"""

from pathlib import Path
from scapy.all import (
    IP,
    TCP,
    UDP,
    ICMP,
    DNS,
    DNSQR,
    Raw,
    wrpcap,
)

CIKTI_KLASORU = Path("test_pcap")
CIKTI_DOSYASI = CIKTI_KLASORU / "p4cket_test_trafik.pcap"

PAKETLER = []


def tcp_paketi(kaynak, hedef, kaynak_port, hedef_port, bayraklar, zaman):
    paket = (
        IP(src=kaynak, dst=hedef)
        / TCP(sport=kaynak_port, dport=hedef_port, flags=bayraklar)
    )
    paket.time = zaman
    PAKETLER.append(paket)


def udp_paketi(kaynak, hedef, kaynak_port, hedef_port, veri, zaman):
    paket = (
        IP(src=kaynak, dst=hedef)
        / UDP(sport=kaynak_port, dport=hedef_port)
        / Raw(load=veri)
    )
    paket.time = zaman
    PAKETLER.append(paket)


def icmp_paketi(kaynak, hedef, zaman):
    paket = IP(src=kaynak, dst=hedef) / ICMP()
    paket.time = zaman
    PAKETLER.append(paket)


def dns_paketi(kaynak, hedef, sorgu, zaman, nxdomain=False):
    cevap_kodu = 3 if nxdomain else 0
    paket = (
        IP(src=kaynak, dst=hedef)
        / UDP(sport=40000, dport=53)
        / DNS(
            id=1234,
            qr=0,
            rcode=cevap_kodu,
            qd=DNSQR(qname=sorgu),
        )
    )
    paket.time = zaman
    PAKETLER.append(paket)


def normal_tcp_trafik():
    """Normal, düşük yoğunluklu TCP trafiği."""
    kaynak = "192.168.1.50"
    hedef = "192.168.1.10"

    for i in range(5):
        zaman = 1700000000.0 + i * 2
        tcp_paketi(kaynak, hedef, 50000 + i, 443, "S", zaman)
        tcp_paketi(hedef, kaynak, 443, 50000 + i, "SA", zaman + 0.02)
        tcp_paketi(kaynak, hedef, 50000 + i, 443, "A", zaman + 0.04)


def port_tarama():
    """Tek kaynaktan çok sayıda farklı porta SYN denemesi."""
    kaynak = "10.10.10.50"
    hedef = "10.10.10.10"
    baslangic = 1700000100.0

    hedef_portlar = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 587, 993, 995, 1433, 3306, 3389,
        5432, 5900, 6379, 8080, 8443,
    ]

    for i, port in enumerate(hedef_portlar):
        tcp_paketi(
            kaynak,
            hedef,
            45000 + i,
            port,
            "S",
            baslangic + i * 0.05,
        )


def syn_anomalisi():
    """Kısa sürede yoğun SYN trafiği."""
    kaynak = "10.10.20.50"
    hedef = "10.10.20.20"
    baslangic = 1700000200.0

    for i in range(80):
        tcp_paketi(
            kaynak,
            hedef,
            46000 + i,
            443,
            "S",
            baslangic + i * 0.01,
        )


def icmp_anomalisi():
    """Yoğun ICMP trafiği."""
    kaynak = "10.10.30.50"
    hedef = "10.10.30.10"
    baslangic = 1700000300.0

    for i in range(60):
        icmp_paketi(
            kaynak,
            hedef,
            baslangic + i * 0.02,
        )


def udp_anomalisi():
    """Yoğun UDP trafiği."""
    kaynak = "10.10.40.50"
    hedef = "10.10.40.10"
    baslangic = 1700000400.0

    for i in range(70):
        udp_paketi(
            kaynak,
            hedef,
            47000 + i,
            9999,
            b"P4CKET-UDP-TEST",
            baslangic + i * 0.015,
        )


def dns_anomalisi():
    """Yüksek DNS hacmi, NXDOMAIN ve uzun/yüksek entropili sorgular."""
    kaynak = "10.10.50.50"
    dns_sunucusu = "10.10.50.53"
    baslangic = 1700000500.0

    normal_sorgular = [
        "www.example.com",
        "mail.example.com",
        "api.example.com",
    ]

    for i in range(20):
        dns_paketi(
            kaynak,
            dns_sunucusu,
            normal_sorgular[i % len(normal_sorgular)],
            baslangic + i * 0.08,
        )

    # NXDOMAIN yoğunluğu
    for i in range(20):
        sorgu = f"olmayan-altalan-{i}.example.invalid"
        dns_paketi(
            kaynak,
            dns_sunucusu,
            sorgu,
            baslangic + 2.0 + i * 0.08,
            nxdomain=True,
        )

    # Uzun ve yüksek entropili görünen yapay sorgular
    entropi_parcalari = [
        "a8f3k2m9x7q1z5v4",
        "q9w8e7r6t5y4u3i2",
        "z1x2c3v4b5n6m7a8",
        "p7o6i5u4y3t2r1e9",
    ]

    for i, parca in enumerate(entropi_parcalari):
        sorgu = f"{parca * 3}.test.invalid"
        dns_paketi(
            kaynak,
            dns_sunucusu,
            sorgu,
            baslangic + 4.0 + i * 0.1,
        )


def periyodik_iletisim():
    """Yaklaşık düzenli aralıklarla tekrarlanan bağlantılar."""
    kaynak = "10.10.60.50"
    hedef = "10.10.60.10"
    baslangic = 1700000600.0

    araliklar = [0, 10.1, 20.0, 30.2, 40.1, 50.0, 60.3]

    for i, fark in enumerate(araliklar):
        zaman = baslangic + fark
        kaynak_port = 48000 + i

        tcp_paketi(
            kaynak,
            hedef,
            kaynak_port,
            443,
            "S",
            zaman,
        )
        tcp_paketi(
            hedef,
            kaynak,
            443,
            kaynak_port,
            "SA",
            zaman + 0.02,
        )


def karisik_normal_trafik():
    """Bazı normal trafik örnekleri; analiz sonucunun sadece anomalilerden oluşmaması için."""
    tcp_paketi(
        "192.168.1.100",
        "93.184.216.34",
        51000,
        443,
        "S",
        1700000700.0,
    )

    udp_paketi(
        "192.168.1.100",
        "192.168.1.1",
        52000,
        53,
        b"normal-dns-test",
        1700000701.0,
    )

    icmp_paketi(
        "192.168.1.100",
        "192.168.1.1",
        1700000702.0,
    )


def main():
    print("=" * 60)
    print("P4CKET - KAPSAMLI SENTETIK TEST PCAP")
    print("=" * 60)
    print()
    print("[*] Yapay test trafigi olusturuluyor...")
    print("[*] Gercek hedeflere paket gonderilmeyecek.")
    print()

    normal_tcp_trafik()
    port_tarama()
    syn_anomalisi()
    icmp_anomalisi()
    udp_anomalisi()
    dns_anomalisi()
    periyodik_iletisim()
    karisik_normal_trafik()

    PAKETLER.sort(key=lambda paket: float(paket.time))

    CIKTI_KLASORU.mkdir(parents=True, exist_ok=True)
    wrpcap(str(CIKTI_DOSYASI), PAKETLER)

    print("[+] Test PCAP hazir!")
    print()
    print(f"    Dosya : {CIKTI_DOSYASI}")
    print(f"    Paket : {len(PAKETLER)}")
    print()
    print("Test edilen senaryolar:")
    print("    [1] Normal TCP trafigi")
    print("    [2] Port tarama")
    print("    [3] SYN anomalisi")
    print("    [4] ICMP anomalisi")
    print("    [5] UDP anomalisi")
    print("    [6] DNS anomalisi")
    print("    [7] Periyodik iletisim")
    print("    [8] Normal karisik trafik")
    print()
    print("P4CKET'i acip bu dosyayi sec:")
    print(f"    {CIKTI_DOSYASI}")


if __name__ == "__main__":
    main()
