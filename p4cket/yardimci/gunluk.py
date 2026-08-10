import logging
import sys


def gunluk_ayarla(seviye: int = logging.WARNING) -> None:
    logging.basicConfig(
        level=seviye,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
