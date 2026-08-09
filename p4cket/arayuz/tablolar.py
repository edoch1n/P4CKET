"""Arayuz tablo bileşenleri."""

from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
from PySide6.QtGui import QColor
from PySide6.QtCore import Qt

from p4cket.modeller import TehditSeviyesi


SEVIYE_RENKLERI = {
    TehditSeviyesi.DUSUK: QColor("#00AA44"),
    TehditSeviyesi.ORTA: QColor("#FFD000"),
    TehditSeviyesi.YUKSEK: QColor("#FF3333"),
    TehditSeviyesi.KRITIK: QColor("#FF0033"),
}


class BulguTablosu(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels(["SEVIYE", "TESPIT", "KAYNAK", "HEDEF", "GUVEN", "PUAN"])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.horizontalHeader().setStretchLastSection(False)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)

    def bulgulari_doldur(self, bulgular: list) -> None:
        self.setRowCount(len(bulgular))
        for satir, bulgu in enumerate(bulgular):
            seviye_metin = bulgu.seviye.value
            seviye_ogesi = QTableWidgetItem(seviye_metin)
            seviye_ogesi.setForeground(SEVIYE_RENKLERI.get(bulgu.seviye, QColor("#D0D0D0")))
            seviye_ogesi.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            self.setItem(satir, 0, seviye_ogesi)
            self.setItem(satir, 1, QTableWidgetItem(bulgu.baslik))
            self.setItem(satir, 2, QTableWidgetItem(bulgu.kaynak))
            self.setItem(satir, 3, QTableWidgetItem(bulgu.hedef or "-"))
            self.setItem(satir, 4, QTableWidgetItem(f"%{bulgu.guven:.1f}"))
            self.setItem(satir, 5, QTableWidgetItem(str(bulgu.puan)))

        self.resizeColumnsToContents()
