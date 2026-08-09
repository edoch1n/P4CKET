# Ornekler

## Ornek PCAP Olusturma

```bash
python araclar/ornek_pcap_olustur.py
```

Bu komut `ornekler/ornek_trafik.pcap` dosyasini olusturur. Dosya sunu icerir:
- Normal TCP trafigi
- Port tarama benzeri trafik (192.168.1.100 -> 192.168.1.20)
- Yuksek DNS sorgu hacmi (192.168.1.30)
- Periyodik baglantilar (192.168.1.40 -> 192.168.1.50)

## Analiz

P4CKET uygulamasini baslatip `ornekler/ornek_trafik.pcap` dosyasini secerek analiz edebilirsiniz.
