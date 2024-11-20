# Anonymizer
IP and MAC address Anonymizer of Wireshark File

Un tool Python per la crittografia e decrittografia degli indirizzi IP e MAC nei file di cattura Wireshark (.pcap/.pcapng). Il tool mantiene la struttura e l'integrità dei pacchetti, modificando solo gli indirizzi di rete per garantire l'anonimato dei dati.

Caratteristiche
  Crittografia/decrittografia di indirizzi IP (IPv4 e IPv6) e MAC
  Processing multi-thread per prestazioni ottimali
  Gestione automatica delle chiavi di crittografia
  Validazione degli indirizzi e gestione degli errori
  Cache LRU per ottimizzare il processing di indirizzi ripetuti
  Supporto per file PCAP e PCAPNG
  Retry automatico per i pacchetti falliti

Requisiti
  Python 3.8 o superiore
  pip (Python package installer)

Dipendenze Python
  pip install scapy
  pip install cryptography
  
Struttura delle Directory
  Il programma si aspetta/crea la seguente struttura di directory:
  .
  ├── FileDaCrittografare/    # Directory per i file di input
  ├── FileCriptati/           # Directory per i file crittografati
  ├── FileDecriptati/         # Directory per i file decrittati
  └── Chiavi/                 # Directory per le chiavi di crittografia
  
Utilizzo Crittografia
  Per crittografare un file di cattura:
    python anonymizer.py capture.pcap or .pcapng
  Il file crittografato verrà salvato in FileCriptati/encrypted_capture.pcap e la chiave di     crittografia in Chiavi/encryption_key_capture.pcap.txt

Decrittografia
  Per decrittografare un file precedentemente crittografato:
    python anonymizer.py capture.pcap --decrypt
  Il programma cercherà automaticamente la chiave di decrittazione in Chiavi/encryption_key_capture.pcap.txt

Opzioni Avanzate
  --threads N: Specifica il numero di thread da utilizzare (default: 4)
  --key KEY: Fornisci direttamente una chiave di decrittazione (solo modalità decrypt)
  
