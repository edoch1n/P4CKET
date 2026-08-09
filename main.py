import sys

from PySide6.QtWidgets import QApplication

from p4cket.arayuz.ana_pencere import AnaPencere
from p4cket.arayuz.tema import temayi_uygula
from p4cket.yardimci.gunluk import gunluk_ayarla


def main():
    gunluk_ayarla()
    uygulama = QApplication(sys.argv)
    uygulama.setApplicationName("P4CKET")
    uygulama.setApplicationVersion("1.0.0")
    temayi_uygula()
    pencere = AnaPencere()
    pencere.show()
    sys.exit(uygulama.exec())


if __name__ == "__main__":
    main()
