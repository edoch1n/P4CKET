import logging
import sys
from contextlib import redirect_stderr
from io import StringIO
from typing import Iterator, Optional

_stderr = StringIO()
with redirect_stderr(_stderr):
    from scapy.all import rdpcap, Packet, IP, TCP, UDP, ICMP, DNS
    from scapy.error import Scapy_Exception

from p4cket.modeller import PaketKaydi

logger = logging.getLogger(__name__)


def _dns_bilgi_cikar(pkt: Packet) -> tuple[Optional[str], Optional[str], Optional[str]]:
    sorgu = None
    cevap = None
    sorgu_tipi = None
    if DNS in pkt:
        try:
            dns_katmani = pkt[DNS]
            if dns_katmani.qdcount > 0 and dns_katmani.qd:
                sorgu = dns_katmani.qd.qname.decode("utf-8", errors="replace").rstrip(".")
                sorgu_tipi = dns_katmani.qd.qtype
            if dns_katmani.ancount > 0 and dns_katmani.an:
                cevaplar = []
                for i in range(dns_katmani.ancount):
                    try:
                        rr = dns_katmani.an[i]
                        if hasattr(rr, "rdata"):
                            cevaplar.append(str(rr.rdata))
                    except Exception:
                        continue
                if cevaplar:
                    cevap = ", ".join(cevaplar)
        except Exception:
            pass
    return sorgu, cevap, str(sorgu_tipi) if sorgu_tipi else None


def pcap_ayristir(dosya_yolu: str) -> tuple[list[PaketKaydi], int, int]:
    paketler: list[PaketKaydi] = []
    atlanan = 0
    toplam = 0

    try:
        scapy_paketler = rdpcap(dosya_yolu)
        toplam = len(scapy_paketler)
    except (Scapy_Exception, OSError, FileNotFoundError) as exc:
        logger.error("PCAP dosyasi okunamadi %s: %s", dosya_yolu, exc)
        raise ValueError(f"Gecersiz veya okunamayan PCAP dosyasi: {exc}") from exc

    for pkt in scapy_paketler:
        try:
            kayit = _paket_ayristir(pkt)
            if kayit:
                paketler.append(kayit)
            else:
                atlanan += 1
        except Exception as exc:
            logger.debug("Bozuk paket atlaniyor: %s", exc)
            atlanan += 1

    logger.info(
        "Parca sonucu: %d paket, %d toplam, %d atlandi",
        len(paketler),
        toplam,
        atlanan,
    )
    return paketler, toplam, atlanan


def _paket_ayristir(pkt: Packet) -> Optional[PaketKaydi]:
    zaman_damgasi = float(pkt.time)
    uzunluk = len(pkt)

    if IP not in pkt:
        return None

    ip_katmani = pkt[IP]
    kaynak_ip = ip_katmani.src
    hedef_ip = ip_katmani.dst
    protokol = str(ip_katmani.proto)

    kaynak_port = None
    hedef_port = None
    tcp_bayraklari = None
    icmp_tipi = None
    icmp_kodu = None
    dns_sorgusu = None
    dns_cevabi = None
    dns_sorgu_tipi = None

    if TCP in pkt:
        tcp_katmani = pkt[TCP]
        kaynak_port = tcp_katmani.sport
        hedef_port = tcp_katmani.dport
        tcp_bayraklari = str(tcp_katmani.flags)
        protokol = "TCP"
    elif UDP in pkt:
        udp_katmani = pkt[UDP]
        kaynak_port = udp_katmani.sport
        hedef_port = udp_katmani.dport
        protokol = "UDP"
        dns_sorgusu, dns_cevabi, dns_sorgu_tipi = _dns_bilgi_cikar(pkt)
    elif ICMP in pkt:
        icmp_katmani = pkt[ICMP]
        icmp_tipi = icmp_katmani.type
        icmp_kodu = icmp_katmani.code
        protokol = "ICMP"
    else:
        dns_sorgusu, dns_cevabi, dns_sorgu_tipi = _dns_bilgi_cikar(pkt)

    return PaketKaydi(
        zaman_damgasi=zaman_damgasi,
        kaynak_ip=kaynak_ip,
        hedef_ip=hedef_ip,
        protokol=protokol,
        kaynak_port=kaynak_port,
        hedef_port=hedef_port,
        uzunluk=uzunluk,
        tcp_bayraklari=tcp_bayraklari,
        dns_sorgusu=dns_sorgusu,
        dns_cevabi=dns_cevabi,
        dns_sorgu_tipi=dns_sorgu_tipi,
        icmp_tipi=icmp_tipi,
        icmp_kodu=icmp_kodu,
    )


def pcap_oku(dosya_yolu: str) -> Iterator[PaketKaydi]:
    try:
        scapy_paketler = rdpcap(dosya_yolu)
    except (Scapy_Exception, OSError, FileNotFoundError) as exc:
        raise ValueError(f"Gecersiz veya okunamayan PCAP dosyasi: {exc}") from exc

    for pkt in scapy_paketler:
        try:
            kayit = _paket_ayristir(pkt)
            if kayit:
                yield kayit
        except Exception:
            continue
