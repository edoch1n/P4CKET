import logging
import os
from datetime import datetime
from typing import Optional

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFrame,
    QPushButton, QLabel, QTableWidget, QTableWidgetItem,
    QProgressBar, QCheckBox, QTextEdit, QFileDialog, QMessageBox,
    QSplitter, QHeaderView
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont

from p4cket.modeller import AnalizOzeti, TehditBulgusu, TehditSeviyesi
from p4cket.motor.analiz_motoru import AnalizMotoru, Ayarlar
from p4cket.rapor.json_rapor import json_rapor_olustur
from p4cket.rapor.txt_rapor import txt_rapor_olustur
from p4cket.arayuz.diyaloglar import DosyaSecimDiyalog, BulguDetayDiyalog, HataMesaji
from p4cket.arayuz.tablolar import BulguTablosu
from p4cket.yardimci.gunluk import gunluk_ayarla

logger = logging.getLogger(__name__)


class AnalizParçaciği(QThread):
    ilerleme_sinyali = Signal(str)
    tamamlandi_sinyali = Signal(object)
    hata_sinyali = Signal(str)

    def __init__(self, pcap_yolu: str, ayarlar: Ayarlar, secili_tespitler: list[str]):
        super().__init__()
        self.pcap_yolu = pcap_yolu
        self.ayarlar = ayarlar
        self.secili_tespitler = secili_tespitler

    def run(self):
        try:
            self.ilerleme_sinyali.emit("PCAP dosyasi okunuyor...")
            motor = AnalizMotoru(self.ayarlar)
            self.ilerleme_sinyali.emit("Paketler ayrıştırılıyor...")
            ozet = motor.analiz_et(self.pcap_yolu, self.secili_tespitler)
            self.ilerleme_sinyali.emit("Analiz tamamlandi.")
            self.tamamlandi_sinyali.emit(ozet)
        except Exception as exc:
            logger.exception("Analiz hatasi")
            self.hata_sinyali.emit(str(exc))


class AnaPencere(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("P4CKET - PCAP Ag Trafigi Analiz ve Tehdit Tespit Sistemi")
        self.setMinimumSize(1000, 650)
        self.resize(1200, 750)

        self.ayarlar = Ayarlar()
        self.secili_tespitler = [
            "port_tarama", "syn_anomalisi", "icmp_anomalisi",
            "udp_anomalisi", "dns_anomalisi", "periyodik_iletisim"
        ]
        self.mevcut_ozet: Optional[AnalizOzeti] = None
        self.analiz_parçaciği: Optional[AnalizParçaciği] = None

        self._olustur()
        self._durum_guncelle("HAZIR", "")

    def _olustur(self):
        merkez_widget = QWidget()
        self.setCentralWidget(merkez_widget)
        ana_duzen = QVBoxLayout(merkez_widget)
        ana_duzen.setContentsMargins(8, 8, 8, 8)
        ana_duzen.setSpacing(8)

        ana_duzen.addWidget(self._ust_bilgi_cubugu())
        ana_duzen.addWidget(self._icerik_paneli())
        ana_duzen.addWidget(self._alt_durum_cubugu())

    def _ust_bilgi_cubugu(self) -> QFrame:
        cerceve = QFrame()
        cerceve.setFrameShape(QFrame.Shape.StyledPanel)
        cerceve.setStyleSheet("background-color: #111111; border: 1px solid #333333;")
        duzen = QHBoxLayout(cerceve)
        duzen.setContentsMargins(12, 8, 12, 8)

        sol = QLabel("P4CKET")
        sol.setStyleSheet("color: #00FF66; font-size: 16pt; font-weight: bold;")
        duzen.addWidget(sol)

        ort = QLabel("PCAP AG TRAFIGI ANALIZ VE TEHDIT TESPIT SISTEMI")
        ort.setStyleSheet("color: #888888; font-size: 9pt;")
        duzen.addWidget(ort, 1)

        sag = QLabel("SURUM 1.0.0")
        sag.setStyleSheet("color: #555555; font-size: 9pt;")
        duzen.addWidget(sag)

        return cerceve

    def _icerik_paneli(self) -> QWidget:
        bolme = QSplitter(Qt.Orientation.Horizontal)

        sol_panel = self._sol_panel()
        bolme.addWidget(sol_panel)

        sag_panel = self._sag_panel()
        bolme.addWidget(sag_panel)

        bolme.setStretchFactor(0, 0)
        bolme.setStretchFactor(1, 1)
        bolme.setSizes([260, 940])

        return bolme

    def _sol_panel(self) -> QFrame:
        cerceve = QFrame()
        cerceve.setFixedWidth(280)
        cerceve.setFrameShape(QFrame.Shape.StyledPanel)
        cerceve.setStyleSheet("background-color: #111111; border: 1px solid #333333;")
        duzen = QVBoxLayout(cerceve)
        duzen.setContentsMargins(10, 10, 10, 10)
        duzen.setSpacing(10)

        analiz_baslik = QLabel("[ ANALIZ KONTROLLERI ]")
        analiz_baslik.setStyleSheet("color: #00FF66; font-weight: bold; font-size: 11pt;")
        duzen.addWidget(analiz_baslik)

        self.dosya_yolu_etiket = QLabel("DOSYA: -")
        self.dosya_yolu_etiket.setStyleSheet("color: #888888; font-size: 9pt;")
        self.dosya_yolu_etiket.setWordWrap(True)
        duzen.addWidget(self.dosya_yolu_etiket)

        self.pcap_sec_butonu = QPushButton("PCAP DOSYASI SEC")
        self.pcap_sec_butonu.clicked.connect(self._pcap_sec)
        duzen.addWidget(self.pcap_sec_butonu)

        self.analiz_baslat_butonu = QPushButton("ANALIZI BASLAT")
        self.analiz_baslat_butonu.clicked.connect(self._analiz_baslat)
        self.analiz_baslat_butonu.setEnabled(False)
        duzen.addWidget(self.analiz_baslat_butonu)

        self.analiz_durdur_butonu = QPushButton("ANALIZI DURDUR")
        self.analiz_durdur_butonu.clicked.connect(self._analiz_durdur)
        self.analiz_durdur_butonu.setEnabled(False)
        duzen.addWidget(self.analiz_durdur_butonu)

        self.temizle_butonu = QPushButton("SONUCLARI TEMIZLE")
        self.temizle_butonu.clicked.connect(self._sonuclari_temizle)
        duzen.addWidget(self.temizle_butonu)

        self.rapor_kaydet_butonu = QPushButton("RAPORU KAYDET")
        self.rapor_kaydet_butonu.clicked.connect(self._raporu_kaydet)
        self.rapor_kaydet_butonu.setEnabled(False)
        duzen.addWidget(self.rapor_kaydet_butonu)

        duzen.addSpacing(10)

        tespit_baslik = QLabel("[ TESPIT MOTORLARI ]")
        tespit_baslik.setStyleSheet("color: #00FF66; font-weight: bold; font-size: 11pt;")
        duzen.addWidget(tespit_baslik)

        self.tespit_kutulari = {}
        tespitler = [
            ("port_tarama", "Port Tarama"),
            ("syn_anomalisi", "SYN Trafik Anomalisi"),
            ("icmp_anomalisi", "ICMP Trafik Anomalisi"),
            ("udp_anomalisi", "UDP Trafik Anomalisi"),
            ("dns_anomalisi", "DNS Anomalisi"),
            ("periyodik_iletisim", "Periyodik Iletisim"),
        ]
        for anahtar, etiket in tespitler:
            kutu = QCheckBox(etiket)
            kutu.setChecked(True)
            kutu.toggled.connect(self._tespit_degisti)
            self.tespit_kutulari[anahtar] = kutu
            duzen.addWidget(kutu)

        duzen.addSpacing(10)

        tumunu_sec_butonu = QPushButton("TUMUNU SEC")
        tumunu_sec_butonu.clicked.connect(self._tumunu_sec)
        duzen.addWidget(tumunu_sec_butonu)

        tumunu_kaldir_butonu = QPushButton("TUMUNU KALDIR")
        tumunu_kaldir_butonu.clicked.connect(self._tumunu_kaldir)
        duzen.addWidget(tumunu_kaldir_butonu)

        duzen.addStretch(1)
        return cerceve

    def _sag_panel(self) -> QFrame:
        cerceve = QFrame()
        cerceve.setFrameShape(QFrame.Shape.StyledPanel)
        cerceve.setStyleSheet("background-color: #080808; border: 1px solid #333333;")
        duzen = QVBoxLayout(cerceve)
        duzen.setContentsMargins(10, 10, 10, 10)
        duzen.setSpacing(8)

        self.analiz_sonucu_baslik = QLabel("[ ANALIZ SONUCU ]")
        self.analiz_sonucu_baslik.setStyleSheet("color: #00FF66; font-weight: bold; font-size: 11pt;")
        duzen.addWidget(self.analiz_sonucu_baslik)

        self.genel_ozet_cerceve = QFrame()
        self.genel_ozet_cerceve.setStyleSheet("background-color: #111111; border: 1px solid #333333;")
        ozet_duzen = QVBoxLayout(self.genel_ozet_cerceve)
        ozet_duzen.setContentsMargins(12, 10, 12, 10)

        self.risk_puani_etiket = QLabel("RISK PUANI: - / 100")
        self.risk_puani_etiket.setStyleSheet("color: #888888; font-size: 12pt; font-weight: bold;")
        ozet_duzen.addWidget(self.risk_puani_etiket)

        self.tehdit_seviyesi_etiket = QLabel("TEHDIT SEVIYESI: -")
        self.tehdit_seviyesi_etiket.setStyleSheet("color: #888888; font-size: 11pt;")
        ozet_duzen.addWidget(self.tehdit_seviyesi_etiket)

        self.istatistik_etiket = QLabel("PAKET: 0 | AKIS: 0 | HOST: 0 | TESPIT: 0")
        self.istatistik_etiket.setStyleSheet("color: #888888; font-size: 9pt;")
        ozet_duzen.addWidget(self.istatistik_etiket)

        self.ilerleme_cubugu = QProgressBar()
        self.ilerleme_cubugu.setVisible(False)
        ozet_duzen.addWidget(self.ilerleme_cubugu)

        self.durum_etiket = QLabel("")
        self.durum_etiket.setStyleSheet("color: #888888; font-size: 9pt;")
        ozet_duzen.addWidget(self.durum_etiket)

        duzen.addWidget(self.genel_ozet_cerceve)

        duzen.addSpacing(8)

        bulgular_baslik = QLabel("TESPITLER")
        bulgular_baslik.setStyleSheet("color: #00FF66; font-weight: bold; font-size: 11pt;")
        duzen.addWidget(bulgular_baslik)

        self.bulgu_tablosu = BulguTablosu()
        self.bulgu_tablosu.setStyleSheet("""
            QTableWidget {
                background-color: #111111;
                color: #D0D0D0;
                gridline-color: #333333;
                border: 1px solid #333333;
            }
            QTableWidget::item {
                padding: 4px;
            }
            QHeaderView::section {
                background-color: #151515;
                color: #00FF66;
                border: 1px solid #333333;
                padding: 4px;
                font-weight: bold;
            }
        """)
        self.bulgu_tablosu.itemClicked.connect(self._bulgu_secildi)
        duzen.addWidget(self.bulgu_tablosu, 1)

        duzen.addSpacing(8)

        detay_baslik = QLabel("BULGU DETAYI")
        detay_baslik.setStyleSheet("color: #00FF66; font-weight: bold; font-size: 11pt;")
        duzen.addWidget(detay_baslik)

        self.detay_metni = QTextEdit()
        self.detay_metni.setReadOnly(True)
        self.detay_metni.setMinimumHeight(120)
        self.detay_metni.setStyleSheet("""
            QTextEdit {
                background-color: #111111;
                color: #D0D0D0;
                border: 1px solid #333333;
                font-family: Consolas, Monaco, monospace;
                font-size: 9pt;
            }
        """)
        duzen.addWidget(self.detay_metni)

        return cerceve

    def _alt_durum_cubugu(self) -> QFrame:
        cerceve = QFrame()
        cerceve.setFixedHeight(28)
        cerceve.setStyleSheet("background-color: #111111; border-top: 1px solid #333333;")
        duzen = QHBoxLayout(cerceve)
        duzen.setContentsMargins(10, 0, 10, 0)

        self.durum_metni = QLabel("HAZIR")
        self.durum_metni.setStyleSheet("color: #00AA44; font-weight: bold;")
        duzen.addWidget(self.durum_metni)

        duzen.addStretch(1)

        sag = QLabel("P4CKET | SAVUNMA AMACLI AG ANALIZI")
        sag.setStyleSheet("color: #555555; font-size: 8pt;")
        duzen.addWidget(sag)

        return cerceve

    def _pcap_sec(self):
        dosya_yolu = DosyaSecimDiyalog.pcap_sec(self)
        if dosya_yolu:
            self.pcap_dosya_yolu = dosya_yolu
            kisa_isim = os.path.basename(dosya_yolu)
            self.dosya_yolu_etiket.setText(f"DOSYA: {kisa_isim}")
            self.analiz_baslat_butonu.setEnabled(True)
            self._durum_guncelle("HAZIR", f"Secili: {kisa_isim}")

    def _analiz_baslat(self):
        if not hasattr(self, "pcap_dosya_yolu") or not self.pcap_dosya_yolu:
            HataMesaji.goster(self, "Uyari", "Once bir PCAP dosyasi secmelisiniz.")
            return

        self._analiz_durdur()
        self._sonuclari_temizle()

        self.analiz_parçaciği = AnalizParçaciği(
            self.pcap_dosya_yolu,
            self.ayarlar,
            self.secili_tespitler,
        )
        self.analiz_parçaciği.ilerleme_sinyali.connect(self._ilerleme_guncelle)
        self.analiz_parçaciği.tamamlandi_sinyali.connect(self._analiz_tamamlandi)
        self.analiz_parçaciği.hata_sinyali.connect(self._analiz_hata)

        self.analiz_parçaciği.start()
        self.analiz_baslat_butonu.setEnabled(False)
        self.analiz_durdur_butonu.setEnabled(True)
        self.pcap_sec_butonu.setEnabled(False)
        self.ilerleme_cubugu.setVisible(True)
        self.ilerleme_cubugu.setRange(0, 0)
        self._durum_guncelle("ANALIZ EDILIYOR", "Islem baslatildi...")

    def _analiz_durdur(self):
        if self.analiz_parçaciği and self.analiz_parçaciği.isRunning():
            self.analiz_parçaciği.terminate()
            self.analiz_parçaciği.wait(3000)
        self.analiz_parçaciği = None
        self.analiz_baslat_butonu.setEnabled(True)
        self.analiz_durdur_butonu.setEnabled(False)
        self.pcap_sec_butonu.setEnabled(True)
        self.ilerleme_cubugu.setVisible(False)
        self._durum_guncelle("DURDURULDU", "")

    def _analiz_tamamlandi(self, ozet: AnalizOzeti):
        self.mevcut_ozet = ozet
        self.analiz_parçaciği = None
        self.analiz_baslat_butonu.setEnabled(True)
        self.analiz_durdur_butonu.setEnabled(False)
        self.pcap_sec_butonu.setEnabled(True)
        self.ilerleme_cubugu.setVisible(False)
        self.rapor_kaydet_butonu.setEnabled(True)

        self.risk_puani_etiket.setText(f"RISK PUANI: {ozet.genel_risk_puani} / 100")
        self.risk_puani_etiket.setStyleSheet(
            f"color: {self._seviye_rengi(ozet.tehdit_seviyesi).name()}; font-size: 12pt; font-weight: bold;"
        )
        self.tehdit_seviyesi_etiket.setText(f"TEHDIT SEVIYESI: {ozet.tehdit_seviyesi.value}")
        self.tehdit_seviyesi_etiket.setStyleSheet(
            f"color: {self._seviye_rengi(ozet.tehdit_seviyesi).name()}; font-size: 11pt;"
        )

        toplam_akis = ozet.tcp_akislari + ozet.udp_akislari
        self.istatistik_etiket.setText(
            f"PAKET: {ozet.toplam_paket} | AKIS: {toplam_akis} | HOST: {ozet.benzersiz_host} | TESPIT: {len(ozet.bulgular)}"
        )

        self.bulgu_tablosu.bulgulari_doldur(ozet.bulgular)

        self._durum_guncelle("ANALIZ TAMAMLANDI", f"{len(ozet.bulgular)} bulgu tespit edildi.")

    def _analiz_hata(self, hata_mesaji: str):
        self.analiz_parçaciği = None
        self.analiz_baslat_butonu.setEnabled(True)
        self.analiz_durdur_butonu.setEnabled(False)
        self.pcap_sec_butonu.setEnabled(True)
        self.ilerleme_cubugu.setVisible(False)
        HataMesaji.goster(self, "Analiz Hatasi", hata_mesaji)
        self._durum_guncelle("HATA", hata_mesaji)

    def _ilerleme_guncelle(self, mesaj: str):
        self.durum_etiket.setText(mesaj)
        self._durum_guncelle("ANALIZ EDILIYOR", mesaj)

    def _bulgu_secildi(self, item: QTableWidgetItem):
        satir = item.row()
        if not self.mevcut_ozet or satir >= len(self.mevcut_ozet.bulgular):
            return
        bulgu = self.mevcut_ozet.bulgular[satir]
        diyalog = BulguDetayDiyalog(bulgu, self)
        diyalog.exec()

    def _raporu_kaydet(self):
        if not self.mevcut_ozet:
            HataMesaji.goster(self, "Uyari", "Kaydedilecek analiz sonucu yok.")
            return

        zaman = datetime.now().strftime("%Y%m%d_%H%M%S")
        varsayilan_isim = f"p4cket_analiz_{zaman}"

        dosya_yolu = DosyaSecimDiyalog.rapor_kaydet(self, varsayilan_isim)
        if not dosya_yolu:
            return

        try:
            if dosya_yolu.endswith(".json"):
                json_rapor_olustur(self.mevcut_ozet, dosya_yolu)
            else:
                txt_rapor_olustur(self.mevcut_ozet, dosya_yolu)
            HataMesaji.bilgi(self, "Bilgi", f"Rapor kaydedildi:\n{dosya_yolu}")
        except Exception as exc:
            HataMesaji.goster(self, "Hata", f"Rapor kaydedilemedi: {exc}")

    def _sonuclari_temizle(self):
        self.mevcut_ozet = None
        self.bulgu_tablosu.setRowCount(0)
        self.detay_metni.clear()
        self.risk_puani_etiket.setText("RISK PUANI: - / 100")
        self.risk_puani_etiket.setStyleSheet("color: #888888; font-size: 12pt; font-weight: bold;")
        self.tehdit_seviyesi_etiket.setText("TEHDIT SEVIYESI: -")
        self.tehdit_seviyesi_etiket.setStyleSheet("color: #888888; font-size: 11pt;")
        self.istatistik_etiket.setText("PAKET: 0 | AKIS: 0 | HOST: 0 | TESPIT: 0")
        self.ilerleme_cubugu.setVisible(False)
        self.durum_etiket.setText("")
        self.rapor_kaydet_butonu.setEnabled(False)
        self.analiz_baslat_butonu.setEnabled(hasattr(self, "pcap_dosya_yolu"))
        self._durum_guncelle("HAZIR", "")

    def _tumunu_sec(self):
        for kutu in self.tespit_kutulari.values():
            kutu.setChecked(True)

    def _tumunu_kaldir(self):
        for kutu in self.tespit_kutulari.values():
            kutu.setChecked(False)

    def _tespit_degisti(self):
        self.secili_tespitler = [
            anahtar for anahtar, kutu in self.tespit_kutulari.items() if kutu.isChecked()
        ]

    def _durum_guncelle(self, durum: str, mesaj: str):
        renk = "#00AA44"
        if durum == "ANALIZ EDILIYOR":
            renk = "#FFD000"
        elif durum == "ANALIZ TAMAMLANDI":
            renk = "#00FF66"
        elif durum == "HATA":
            renk = "#FF3333"
        self.durum_metni.setText(durum)
        self.durum_metni.setStyleSheet(f"color: {renk}; font-weight: bold;")
        if mesaj:
            self.durum_etiket.setText(mesaj)

    @staticmethod
    def _seviye_rengi(seviye: TehditSeviyesi) -> QColor:
        renkler = {
            TehditSeviyesi.DUSUK: QColor("#00AA44"),
            TehditSeviyesi.ORTA: QColor("#FFD000"),
            TehditSeviyesi.YUKSEK: QColor("#FF3333"),
            TehditSeviyesi.KRITIK: QColor("#FF0033"),
        }
        return renkler.get(seviye, QColor("#D0D0D0"))

    def closeEvent(self, event):
        if self.analiz_parçaciği and self.analiz_parçaciği.isRunning():
            self.analiz_parçaciği.terminate()
            self.analiz_parçaciği.wait(3000)
        super().closeEvent(event)
