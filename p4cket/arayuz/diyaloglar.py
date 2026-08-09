"""Arayuz diyaloglari."""

import os
from datetime import datetime
from typing import Optional

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QFileDialog, QMessageBox
)
from PySide6.QtGui import QColor
from PySide6.QtCore import Qt

from p4cket.modeller import TehditBulgusu, TehditSeviyesi


SEVIYE_RENKLERI = {
    TehditSeviyesi.DUSUK: QColor("#00AA44"),
    TehditSeviyesi.ORTA: QColor("#FFD000"),
    TehditSeviyesi.YUKSEK: QColor("#FF3333"),
    TehditSeviyesi.KRITIK: QColor("#FF0033"),
}


class BulguDetayDiyalog(QDialog):
    def __init__(self, bulgu: TehditBulgusu, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Bulgu Detayi")
        self.setMinimumWidth(500)
        self._bulgu = bulgu
        self._olustur()

    def _olustur(self):
        duzen = QVBoxLayout(self)

        baslik = QLabel(self._bulgu.baslik)
        baslik.setStyleSheet(f"color: {SEVIYE_RENKLERI.get(self._bulgu.seviye, QColor('#D0D0D0')).name()}; font-size: 14pt; font-weight: bold;")
        duzen.addWidget(baslik)

        detay_metni = self._detay_metni()
        metin_alani = QTextEdit()
        metin_alani.setReadOnly(True)
        metin_alani.setText(detay_metni)
        duzen.addWidget(metin_alani)

        kapat_butonu = QPushButton("KAPAT")
        kapat_butonu.clicked.connect(self.accept)
        duzen.addWidget(kapat_butonu)

    def _detay_metni(self) -> str:
        b = self._bulgu
        satirlar = [
            f"TESPIT: {b.baslik}",
            f"SEVIYE: {b.seviye.value}",
            f"KAYNAK IP: {b.kaynak}",
            f"HEDEF IP: {b.hedef or '-'}",
            f"GUVEN: %{b.guven:.1f}",
            f"RISK PUANI: {b.puan} / 100",
            "",
            "KANIT:",
        ]
        for k, v in b.kanit.items():
            satirlar.append(f"- {k}: {v}")
        satirlar.append("")
        satirlar.append(f"ONERILEN AKSIYON: {b.onerilen_aksiyon or '-'}")
        return "\n".join(satirlar)


class DosyaSecimDiyalog:
    @staticmethod
    def pcap_sec(ebeveyn=None) -> Optional[str]:
        dosya_yolu, _ = QFileDialog.getOpenFileName(
            ebeveyn,
            "PCAP Dosyasi Sec",
            "",
            "PCAP Dosyalari (*.pcap *.pcapng);;Tum Dosyalar (*.*)",
        )
        return dosya_yolu if dosya_yolu else None

    @staticmethod
    def rapor_kaydet(ebeveyn=None, varsayilan_isim: str = "") -> Optional[str]:
        dosya_yolu, _ = QFileDialog.getSaveFileName(
            ebeveyn,
            "Raporu Kaydet",
            varsayilan_isim,
            "JSON Dosyalari (*.json);;Metin Dosyalari (*.txt);;Tum Dosyalar (*.*)",
        )
        return dosya_yolu if dosya_yolu else None


class HataMesaji:
    @staticmethod
    def goster(ebeveyn, baslik: str, mesaj: str) -> None:
        QMessageBox.critical(ebeveyn, baslik, mesaj)

    @staticmethod
    def bilgi(ebeveyn, baslik: str, mesaj: str) -> None:
        QMessageBox.information(ebeveyn, baslik, mesaj)
