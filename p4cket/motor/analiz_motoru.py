import logging
from datetime import datetime
from typing import Optional

from p4cket.modeller import AnalizOzeti, TehditBulgusu, TehditSeviyesi
from p4cket.motor.akis_motoru import akislari_olustur
from p4cket.motor.pcap_ayristirici import pcap_ayristir
from p4cket.motor.puanlama import seviye_hesapla
from p4cket.yardimci.sabitler import Ayarlar
from p4cket.tespit.port_tarama import PortTaramaTespit
from p4cket.tespit.syn_anomalisi import SynAnomalisiTespit
from p4cket.tespit.icmp_anomalisi import IcmpAnomalisiTespit
from p4cket.tespit.udp_anomalisi import UdpAnomalisiTespit
from p4cket.tespit.dns_anomalisi import DnsAnomalisiTespit
from p4cket.tespit.periyodik_iletisim import PeriyodikIletisimTespit

logger = logging.getLogger(__name__)


class AnalizMotoru:
    def __init__(self, ayarlar: Optional[Ayarlar] = None):
        self.ayarlar = ayarlar or Ayarlar()

    def analiz_et(self, pcap_yolu: str, secili_tespitler: Optional[list[str]] = None) -> AnalizOzeti:
        logger.info("Analiz basliyor: %s", pcap_yolu)

        paketler, toplam_paket, atlanan = pcap_ayristir(pcap_yolu)
        if not paketler:
            return self._bos_ozet(pcap_yolu)

        akislar = akislari_olustur(paketler)
        bulgular: list[TehditBulgusu] = []

        if secili_tespitler is None or "port_tarama" in secili_tespitler:
            port_tarama = PortTaramaTespit(self.ayarlar.port_tarama)
            bulgular.extend(port_tarama.calistir(akislar))

        if secili_tespitler is None or "syn_anomalisi" in secili_tespitler:
            syn = SynAnomalisiTespit(self.ayarlar.trafik_anomalisi)
            bulgular.extend(syn.calistir(akislar))

        if secili_tespitler is None or "icmp_anomalisi" in secili_tespitler:
            icmp = IcmpAnomalisiTespit(self.ayarlar.trafik_anomalisi)
            bulgular.extend(icmp.calistir(akislar))

        if secili_tespitler is None or "udp_anomalisi" in secili_tespitler:
            udp = UdpAnomalisiTespit(self.ayarlar.trafik_anomalisi)
            bulgular.extend(udp.calistir(akislar))

        if secili_tespitler is None or "dns_anomalisi" in secili_tespitler:
            dns = DnsAnomalisiTespit(self.ayarlar.dns_anomalisi)
            bulgular.extend(dns.calistir(paketler))

        if secili_tespitler is None or "periyodik_iletisim" in secili_tespitler:
            periyodik = PeriyodikIletisimTespit(self.ayarlar.periyodik_iletisim)
            bulgular.extend(periyodik.calistir(akislar))

        genel_puan = self._genel_puan_hesapla(bulgular)
        tehdit_seviyesi = seviye_hesapla(genel_puan, self.ayarlar.puanlama)
        oneriler = self._oneriler_olustur(bulgular)

        benzersiz_host = len(
            set(p.kaynak_ip for p in paketler) | set(p.hedef_ip for p in paketler)
        )
        tcp_akislari = sum(1 for a in akislar if a.protokol == "TCP")
        udp_akislari = sum(1 for a in akislar if a.protokol == "UDP")
        icmp_paketleri = sum(1 for p in paketler if p.protokol == "ICMP")
        dns_paketleri = sum(1 for p in paketler if p.dns_sorgusu)

        ozet = AnalizOzeti(
            pcap_dosya=pcap_yolu,
            analiz_zamani=datetime.now().isoformat(),
            toplam_paket=len(paketler),
            benzersiz_host=benzersiz_host,
            tcp_akislari=tcp_akislari,
            udp_akislari=udp_akislari,
            icmp_paketleri=icmp_paketleri,
            dns_paketleri=dns_paketleri,
            bulgular=bulgular,
            genel_risk_puani=genel_puan,
            tehdit_seviyesi=tehdit_seviyesi,
            oneriler=oneriler,
        )

        logger.info(
            "Analiz tamamlandi: %d bulgu, puan %d, seviye %s",
            len(bulgular),
            genel_puan,
            tehdit_seviyesi,
        )
        return ozet

    def _bos_ozet(self, pcap_yolu: str) -> AnalizOzeti:
        return AnalizOzeti(
            pcap_dosya=pcap_yolu,
            analiz_zamani=datetime.now().isoformat(),
            toplam_paket=0,
            benzersiz_host=0,
            tcp_akislari=0,
            udp_akislari=0,
            icmp_paketleri=0,
            dns_paketleri=0,
            bulgular=[],
            genel_risk_puani=0,
            tehdit_seviyesi=TehditSeviyesi.DUSUK,
            oneriler=["PCAP dosyasinda analiz edilebilir paket bulunamadi."],
        )

    def _genel_puan_hesapla(self, bulgular: list[TehditBulgusu]) -> int:
        if not bulgular:
            return 0
        agirlikli_toplam = 0.0
        toplam_agirlik = 0.0
        for b in bulgular:
            agirlik = b.guven / 100.0
            agirlikli_toplam += b.puan * agirlik
            toplam_agirlik += agirlik
        if toplam_agirlik == 0:
            return 0
        return min(100, int(agirlikli_toplam / toplam_agirlik))

    def _oneriler_olustur(self, bulgular: list[TehditBulgusu]) -> list[str]:
        oneriler = []
        gorulen = set()
        for b in bulgular:
            if b.onerilen_aksiyon and b.onerilen_aksiyon not in gorulen:
                oneriler.append(b.onerilen_aksiyon)
                gorulen.add(b.onerilen_aksiyon)
        return oneriler
