from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QPalette, QColor
from PySide6.QtCore import Qt


def temayi_uygula() -> None:
    uygulama = QApplication.instance()
    if uygulama is None:
        return

    palet = QPalette()
    palet.setColor(QPalette.ColorRole.Window, QColor("#080808"))
    palet.setColor(QPalette.ColorRole.WindowText, QColor("#D0D0D0"))
    palet.setColor(QPalette.ColorRole.Base, QColor("#111111"))
    palet.setColor(QPalette.ColorRole.AlternateBase, QColor("#151515"))
    palet.setColor(QPalette.ColorRole.Text, QColor("#D0D0D0"))
    palet.setColor(QPalette.ColorRole.Button, QColor("#111111"))
    palet.setColor(QPalette.ColorRole.ButtonText, QColor("#00FF66"))
    palet.setColor(QPalette.ColorRole.Highlight, QColor("#00FF66"))
    palet.setColor(QPalette.ColorRole.HighlightedText, QColor("#000000"))
    uygulama.setPalette(palet)

    uygulama.setStyleSheet("""
        QMainWindow {
            background-color: #080808;
            color: #D0D0D0;
        }
        QWidget {
            background-color: #080808;
            color: #D0D0D0;
            font-family: Consolas, Monaco, monospace;
            font-size: 10pt;
        }
        QFrame {
            background-color: #111111;
            border: 1px solid #333333;
        }
        QPushButton {
            background-color: #111111;
            color: #00FF66;
            border: 1px solid #00AA44;
            padding: 6px 12px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #00AA44;
            color: #000000;
        }
        QPushButton:pressed {
            background-color: #00FF66;
            color: #000000;
        }
        QPushButton:disabled {
            background-color: #222222;
            color: #555555;
            border: 1px solid #333333;
        }
        QLabel {
            color: #D0D0D0;
            background-color: transparent;
        }
        QCheckBox {
            color: #D0D0D0;
            spacing: 6px;
        }
        QCheckBox::indicator {
            width: 14px;
            height: 14px;
            border: 1px solid #333333;
            background-color: #111111;
        }
        QCheckBox::indicator:checked {
            background-color: #00FF66;
            border: 1px solid #00FF66;
        }
        QProgressBar {
            border: 1px solid #333333;
            border-radius: 0px;
            text-align: center;
            background-color: #111111;
            color: #D0D0D0;
        }
        QProgressBar::chunk {
            background-color: #00FF66;
        }
        QTableWidget {
            background-color: #111111;
            color: #D0D0D0;
            gridline-color: #333333;
            border: 1px solid #333333;
            selection-background-color: #00AA44;
            selection-color: #000000;
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
        QTextEdit {
            background-color: #111111;
            color: #D0D0D0;
            border: 1px solid #333333;
        }
        QLineEdit {
            background-color: #111111;
            color: #D0D0D0;
            border: 1px solid #333333;
            padding: 4px;
        }
        QStatusBar {
            background-color: #111111;
            color: #D0D0D0;
            border-top: 1px solid #333333;
        }
    """)
