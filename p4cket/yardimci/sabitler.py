from dataclasses import dataclass


@dataclass
class PortTaramaSabitleri:
    port_esigi: int = 15
    zaman_penceresi: float = 10.0
    host_esigi: int = 10
    syn_orani_esigi: float = 0.8


@dataclass
class TrafikAnomalisiSabitleri:
    syn_paket_esigi: int = 500
    icmp_paket_esigi: int = 200
    udp_paket_esigi: int = 1000
    zaman_penceresi: float = 5.0


@dataclass
class DnsAnomalisiSabitleri:
    sorgu_esigi: int = 100
    benzersiz_domain_esigi: int = 50
    nxdomain_orani_esigi: float = 0.5
    maks_sorgu_uzunlugu: int = 100
    entropi_esigi: float = 4.0


@dataclass
class PeriyodikIletisimSabitleri:
    min_gözlem: int = 5
    duzenlilik_esigi: float = 0.7
    maks_gecikme_saniye: float = 5.0


@dataclass
class PuanlamaSabitleri:
    dusuk_ust: int = 39
    orta_ust: int = 69
    yuksek_ust: int = 89
    kritik_alt: int = 90


@dataclass
class Ayarlar:
    port_tarama: PortTaramaSabitleri = None
    trafik_anomalisi: TrafikAnomalisiSabitleri = None
    dns_anomalisi: DnsAnomalisiSabitleri = None
    periyodik_iletisim: PeriyodikIletisimSabitleri = None
    puanlama: PuanlamaSabitleri = None

    def __post_init__(self):
        if self.port_tarama is None:
            self.port_tarama = PortTaramaSabitleri()
        if self.trafik_anomalisi is None:
            self.trafik_anomalisi = TrafikAnomalisiSabitleri()
        if self.dns_anomalisi is None:
            self.dns_anomalisi = DnsAnomalisiSabitleri()
        if self.periyodik_iletisim is None:
            self.periyodik_iletisim = PeriyodikIletisimSabitleri()
        if self.puanlama is None:
            self.puanlama = PuanlamaSabitleri()
