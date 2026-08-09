"""Risk puanlama sistemi."""

from p4cket.modeller import TehditSeviyesi
from p4cket.yardimci.sabitler import PuanlamaSabitleri


def seviye_hesapla(puan: int, sabitler: PuanlamaSabitleri | None = None) -> TehditSeviyesi:
    if sabitler is None:
        sabitler = PuanlamaSabitleri()
    if puan <= sabitler.dusuk_ust:
        return TehditSeviyesi.DUSUK
    if puan <= sabitler.orta_ust:
        return TehditSeviyesi.ORTA
    if puan <= sabitler.yuksek_ust:
        return TehditSeviyesi.YUKSEK
    return TehditSeviyesi.KRITIK


def puani_normalize_et(ham_puan: float, maks_puan: float = 100.0) -> int:
    if maks_puan <= 0:
        return 0
    normalize = int((ham_puan / maks_puan) * 100)
    return max(0, min(100, normalize))
