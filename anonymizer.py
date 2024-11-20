import os
import argparse
import tempfile
import shutil
from scapy.all import *
from scapy.utils import PcapReader
import threading
from queue import Queue, Empty
import time
from typing import Dict, Optional, List, Tuple, DefaultDict
import logging
from cryptography.fernet import Fernet
import ipaddress
import re
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, Future
from collections import defaultdict
from dataclasses import dataclass
from abc import ABC, abstractmethod
import base64

# Custom exceptions
class ProcessingError(Exception):
    """Eccezione sollevata per errori di processing critici."""
    pass

class AddressNotFoundError(Exception):
    """Eccezione sollevata quando un indirizzo non viene trovato."""
    pass

class ProjectDirectories:
    """
    Gestisce i percorsi delle directory del progetto.
    Fornisce funzionalità per:
    - Setup iniziale delle directory
    - Validazione e gestione dei percorsi
    - Gestione centralizzata delle operazioni sui file
    """
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    INPUT_DIR = os.path.join(BASE_DIR, "FileDaCrittografare")
    ENCRYPTED_DIR = os.path.join(BASE_DIR, "FileCriptati")
    DECRYPTED_DIR = os.path.join(BASE_DIR, "FileDecriptati")
    KEYS_DIR = os.path.join(BASE_DIR, "Chiavi")
    
    @classmethod
    def setup_project_directories(cls) -> None:
        """
        Crea le directory necessarie se non esistono.
        Deve essere chiamato all'avvio del programma.
        
        Raises:
            RuntimeError: Se non è possibile creare una directory
        """
        required_dirs = [
            cls.INPUT_DIR,
            cls.ENCRYPTED_DIR, 
            cls.DECRYPTED_DIR,
            cls.KEYS_DIR
        ]
        
        for dir_path in required_dirs:
            if not os.path.exists(dir_path):
                try:
                    os.makedirs(dir_path)
                    logging.info(f"Created project directory: {dir_path}")
                except Exception as e:
                    raise RuntimeError(f"Failed to create required directory {dir_path}: {e}")
            else:
                logging.info(f"Project directory exists: {dir_path}")

    @classmethod
    def get_input_path(cls, filename: str) -> str:
        """
        Costruisce il percorso completo per un file di input.
        
        Args:
            filename: Nome del file
            
        Returns:
            str: Percorso completo nel formato BASE_DIR/FileDaCrittografare/filename
        """
        return os.path.join(cls.INPUT_DIR, filename)

    @classmethod
    def get_output_path(cls, filename: str, is_encrypting: bool) -> str:
        """
        Costruisce il percorso completo per un file di output.
        
        Args:
            filename: Nome del file
            is_encrypting: True se stiamo crittando, False se decrittando
            
        Returns:
            str: Percorso completo nel formato BASE_DIR/FileCriptati(o FileDecriptati)/filename
        """
        output_dir = cls.ENCRYPTED_DIR if is_encrypting else cls.DECRYPTED_DIR
        prefix = "encrypted" if is_encrypting else "decrypted"
        output_filename = f"{prefix}_{filename}"
        return os.path.join(output_dir, output_filename)

    @classmethod
    def get_key_path(cls, input_filename: str) -> str:
        """
        Costruisce il percorso completo per un file chiave.
        
        Args:
            input_filename: Nome del file di input
            
        Returns:
            str: Percorso completo nel formato BASE_DIR/chiavi/encryption_key_filename.txt
        """
        return os.path.join(cls.KEYS_DIR, f"encryption_key_{input_filename}.txt")

    @classmethod
    def verify_directory_structure(cls) -> bool:
        """
        Verifica che la struttura delle directory sia corretta.
        
        Returns:
            bool: True se la struttura è corretta
            
        Raises:
            RuntimeError: Se la struttura non è valida
        """
        required_dirs = [
            cls.INPUT_DIR,
            cls.ENCRYPTED_DIR,
            cls.DECRYPTED_DIR,
            cls.KEYS_DIR
        ]
        
        for dir_path in required_dirs:
            if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
                raise RuntimeError(f"Invalid directory structure. Missing or invalid directory: {dir_path}")
        
        return True
@dataclass
class BatchResult:
    """
    Contenitore per i risultati del processing di un batch di pacchetti.
    
    Attributes:
        processed_packets: Lista dei pacchetti processati con successo
        failed_packets: Lista dei pacchetti che hanno fallito il processing
        errors: Lista degli errori incontrati durante il processing
        processing_time: Tempo totale impiegato per processare il batch
    """
    processed_packets: List[Packet]
    failed_packets: List[Packet]
    errors: List[Exception]
    processing_time: float

@dataclass
class ProcessingStats:
    """
    Mantiene le statistiche del processing dei pacchetti.
    
    Attributes:
        total_packets: Numero totale di pacchetti da processare
        processed_packets: Numero di pacchetti processati con successo
        retry_count: Numero di retry effettuati
    """
    total_packets: int = 0
    processed_packets: int = 0
    retry_count: int = 0

class BatchProcessor:
    """
    Gestisce il processing dei batch di pacchetti e la logica di retry.
    
    Questa classe si occupa di:
    - Aggregare i pacchetti in batch di dimensione configurabile
    - Gestire il processing parallelo tramite thread pool
    - Implementare la logica di retry per i pacchetti falliti
    
    Attributes:
        batch_size: Dimensione standard di un batch
        current_batch: Lista dei pacchetti nel batch corrente
        _lock: Lock per garantire thread-safety nelle operazioni sui batch
    """
    def __init__(self, batch_size: int = 1000):
        """
        Inizializza il processore di batch.
        
        Args:
            batch_size: Numero massimo di pacchetti per batch (default: 1000)
        """
        self.batch_size = batch_size
        self.current_batch: List[Packet] = []
        self._lock = threading.Lock()

    def add_packet(self, packet: Packet) -> Optional[List[Packet]]:
        """
        Aggiunge un pacchetto al batch corrente e restituisce il batch se completo.
        
        Args:
            packet: Il pacchetto da aggiungere al batch
            
        Returns:
            Optional[List[Packet]]: Il batch completo se ha raggiunto batch_size,
                                  None altrimenti
                                  
        Thread Safety:
            Metodo thread-safe grazie all'uso di _lock
        """
        with self._lock:
            self.current_batch.append(packet)
            if len(self.current_batch) >= self.batch_size:
                completed_batch = self.current_batch
                self.current_batch = []
                return completed_batch
        return None

    def get_remaining(self) -> List[Packet]:
        """
        Recupera i pacchetti rimanenti che non formano un batch completo.
        
        Returns:
            List[Packet]: Lista dei pacchetti rimanenti
            
        Notes:
            Svuota il batch corrente dopo aver restituito i pacchetti
        """
        with self._lock:
            remaining = self.current_batch
            self.current_batch = []
            return remaining

    def process_batch(self, batch: List[Packet], thread_pool: ThreadPoolExecutor,
                     process_func, write_func, batch_size: int = 1000) -> List[Packet]:
        """
        Processa un batch di pacchetti utilizzando il thread pool.
        
        Args:
            batch: Lista di pacchetti da processare
            thread_pool: ThreadPoolExecutor da utilizzare
            process_func: Funzione per processare il batch
            write_func: Funzione per scrivere i risultati
            batch_size: Dimensione del batch
            
        Returns:
            List[Packet]: Lista dei pacchetti che hanno fallito il processing
        """
        future = thread_pool.submit(process_func, batch)
        result = future.result()
        write_func(result)
        return result.failed_packets

    def process_with_retry(self, failed_packets: List[Packet], thread_pool: ThreadPoolExecutor,
                          process_func, write_func, retry_batch_size: int = 100) -> List[Packet]:
        """
        Processa i pacchetti falliti in batch più piccoli.
        
        Args:
            failed_packets: Lista dei pacchetti da riprocessare
            thread_pool: ThreadPoolExecutor da utilizzare
            process_func: Funzione per processare il batch
            write_func: Funzione per scrivere i risultati
            retry_batch_size: Dimensione del batch per i retry
            
        Returns:
            List[Packet]: Lista dei pacchetti che hanno fallito anche il retry
            
        Notes:
            Usa batch più piccoli per aumentare la probabilità di successo
        """
        new_failed_packets = []
        
        for i in range(0, len(failed_packets), retry_batch_size):
            retry_batch = failed_packets[i:i + retry_batch_size]
            new_failed_packets.extend(
                self.process_batch(retry_batch, thread_pool, process_func, 
                                 write_func, retry_batch_size)
            )
        
        return new_failed_packets
    
#Validator è una classe con soli metodi statici (@staticmethod), quindi non ha bisogno di essere istanziata 
class Validator:
    """
    Classe di utilità per la validazione degli indirizzi e altro.
    """
    @staticmethod
    def is_valid_mac(address: str) -> bool:
        """
        Verifica se l'indirizzo MAC è valido.
        
        Args:
            address: Indirizzo da verificare
            
        Returns:
            bool: True se l'indirizzo è un MAC valido, False altrimenti
            
        Notes:
            Accetta formati con ':' o '-' come separatori
        """
        if not address:
            logging.info(f"Validation failed for empty MAC address")
            return False
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        if mac_pattern.match(address):
            logging.info(f"Validated MAC address: {address}")
            return True
        else:
            logging.info(f"Invalid MAC address: {address}")
            return False
        return bool(mac_pattern.match(address))
    
    @staticmethod
    def is_valid_ip(address: str) -> bool:
        """
        Verifica se l'indirizzo IP è valido.
        
        Args:
            address: Indirizzo da verificare
            
        Returns:
            bool: True se l'indirizzo è un IP valido, False altrimenti
            
        Notes:
            Supporta sia IPv4 che IPv6
        """
        if not address:
            logging.info(f"Validation failed for empty IP address")
            return False
        try:
            ipaddress.ip_address(address)
            logging.info(f"Validated IP address: {address}")
            return True
        except ValueError:
            logging.info(f"Invalid IP address: {address}")
            return False
    
    @staticmethod
    def validate_file_extension(filepath: str) -> bool:
        """Verifica che l'estensione del file sia valida."""
        ext = os.path.splitext(filepath)[1].lower()
        return ext in ['.pcap', '.pcapng']
    
    @staticmethod
    def validate_pcap_file(filepath: str) -> bool:
        """
        Verifica validità completa del file pcap/pcapng.
        
        Args:
            filepath: Path del file da validare
            
        Returns:
            bool: True se il file è valido
            
        Raises:
            FileNotFoundError: Se il file non esiste
            ValueError: Se il file non è valido
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
    
        if not Validator.validate_file_extension(filepath):
            raise ValueError(f"Unsupported file extension")
            
        try:
            with PcapReader(filepath) as reader:
                next(reader)
            return True
        except Exception as e:
            raise ValueError(f"Invalid PCAP file: {e}")
    
    @staticmethod    
    def get_validated_path(base_dir: str, filename: str) -> str:
        """
        Costruisce e valida il percorso completo di un file.
        
        Args:
            base_dir: Directory base
            filename: Nome del file
            
        Returns:
            str: Percorso completo validato
            
        Raises:
            FileNotFoundError, ValueError
        """
        filepath = os.path.join(base_dir, filename)
        Validator.validate_pcap_file(filepath)
        return filepath


class NetworkShardedDict:
    """
    Gestisce gli indirizzi con sharding e caching LRU.
    
    Questa classe implementa:
    - Sharding degli indirizzi per ottimizzare l'accesso concorrente
    - Cache LRU per gli indirizzi più frequentemente acceduti
    - Accesso thread-safe ai dati
    
    Attributes:
        _shards: Lista di dizionari per lo sharding
        _locks: Lock per ogni shard
        _hot_cache: Cache LRU per accessi veloci
        _hot_cache_lock: Lock per la cache
    """
    def __init__(self, num_shards: int, max_cache_entries: int = 10000):
        """
        Inizializza il dizionario shardato.
        
        Args:
            num_shards: Numero di shards
            max_cache_entries: Dimensione massima della cache LRU
        """
        self._shards: List[Dict[str, str]] = [
            {} for _ in range(num_shards)
        ]
        self._locks: List[threading.RLock] = [
            threading.RLock() for _ in range(num_shards)
        ]
        self._hot_cache = collections.OrderedDict()
        self._max_cache_entries = max_cache_entries
        self._hot_cache_lock = threading.RLock()
        
    def _get_shard_index(self, address: str) -> int:
        """
        Determina l'indice dello shard per un indirizzo.
        
        Args:
            address: Indirizzo da processare
            
        Returns:
            Indice dello shard dove memorizzare/recuperare l'indirizzo
        """
        try:
            if Validator.is_valid_ip(address):
                ip_parts = address.split('.')
                return int(ip_parts[-1]) % len(self._shards) #Usa l'ultimo ottetto dell'IP per lo sharding.
            elif Validator.is_valid_mac(address):
                mac_parts = address.split(':')
                return (int(mac_parts[-2], 16) + int(mac_parts[-1], 16)) % len(self._shards)#Usa gli ultimi due byte per lo sharding.
            else:
                shard_idx= hash(address) % len(self._shards)
                
            logging.info(f"Shard index for address {address}: {shard_idx}")
            return shard_idx
        except Exception as e:
            logging.error(f"Error in shard calculation for {address}: {e}")
            return hash(address) % len(self._shards)
        
    def _update_cache(self, address: str, shard_idx: int, value: str) -> None:
        """
        Aggiorna la cache LRU.
        Nota: questo metodo assume che il caller abbia già acquisito _hot_cache_lock
        """
        try:
            if address in self._hot_cache: #Se indirizzo già nella cache lo rimuove, lo andremo a reinserire come più recente
                del self._hot_cache[address]
                logging.info(f"Removed address {address} from cache to update it.")
            
            if len(self._hot_cache) >= self._max_cache_entries: #se cache piena
                old_key, _ = self._hot_cache.popitem(last=False)
                logging.info(f"Cache full. Evicted oldest address: {old_key}")
                #self._hot_cache.popitem(last=False) #rimuovo il più vecchio
            
            self._hot_cache[address] = (shard_idx, value)
            logging.info(f"Added address {address} to cache with value: {value[:50]}")
        except Exception as e:
            logging.error(f"Failed to update cache for {address}: {e}")
    
    def get(self, address: str) -> str:
        """
        Recupera un valore dalla cache o dallo shard appropriato.
        
        Args:
            address: Indirizzo da cercare
            
        Returns:
            Il valore associato all'indirizzo
            
        Raises:
            AddressNotFoundError: Se l'indirizzo non viene trovato
        """
        try:
            # Prima controlla la cache
            with self._hot_cache_lock:
                if cached := self._hot_cache.get(address):
                    self._hot_cache.move_to_end(address)
                    logging.info(f"Cache hit for address {address}")
                    return cached[1]
            
            # Cache miss, cerca nello shard
            shard_idx = self._get_shard_index(address)
            
            value = None
            # Prima ottieni il valore dallo shard
            with self._locks[shard_idx]:
                value = self._shards[shard_idx].get(address)
            
            if value:
                # Se il valore è stato trovato, aggiorna la cache
                with self._hot_cache_lock:
                    self._update_cache(address, shard_idx, value)
                logging.info(f"Address {address} found in shard {shard_idx}")
                return value
            
            logging.error(f"Address {address} not found in cache or shards.")
            raise AddressNotFoundError(
                f"Address {address} not found in cache or shards. "
                "This might indicate data corruption or synchronization issues."
            )
            
        except AddressNotFoundError:
            raise
        except Exception as e:
            logging.error(f"Error retrieving value for {address}: {e}")
            raise
    
    def set(self, address: str, value: str) -> None:
        """
        Memorizza un valore nello shard appropriato e aggiorna la cache.
        
        Args:
            address: Indirizzo da memorizzare
            value: Valore da associare all'indirizzo
            
        Thread Safety:
            Metodo thread-safe grazie all'uso di lock separati per shard e cache
        """
        try:
            shard_idx = self._get_shard_index(address)
            
            # Prima aggiorna lo shard
            with self._locks[shard_idx]:
                self._shards[shard_idx][address] = value
                logging.info(f"Set address {address} in shard {shard_idx} with value: {value[:50]}")
                
            # Poi, separatamente, aggiorna la cache
            with self._hot_cache_lock:
                self._update_cache(address, shard_idx, value)
                
        except Exception as e:
            logging.error(f"Error setting value for {address}: {e}")
            raise

class BaseAddressCryptographer(ABC):
    """
    Classe base astratta per la crittografia/decrittografia degli indirizzi.
    
    Fornisce le funzionalità base per:
    - Gestione della cache degli indirizzi
    - Crittografia/decrittografia usando Fernet
    - Validazione base degli indirizzi
    
    Attributes:
        _address_map: Dizionario shardato per la cache degli indirizzi
        _fernet: Istanza di Fernet per crittografia
        _is_encrypting: Flag che indica se stiamo crittando o decrittando
    """
    def __init__(self, fernet: Fernet, is_encrypting: bool, num_shards: int):
        """
        Inizializza il cryptographer base.
        
        Args:
            fernet: Istanza di Fernet per la crittografia
            is_encrypting: True per crittografia, False per decrittografia
            num_shards: Numero di shards per il dizionario degli indirizzi
        """
        self._address_map = NetworkShardedDict(num_shards=num_shards)
        self._fernet = fernet
        self._is_encrypting = is_encrypting

    @abstractmethod
    def _validate_address(self, address: str) -> bool:
        """
        Metodo base, per validazione dell'indirizzo.
        
        Args:
            address: Indirizzo da validare
            
        Returns:
            True se l'indirizzo è valido, False altrimenti
            
        Notes:
            Metodo destinato ad essere sovrascritto dalle classi figlie
        """
        pass
    
    def process_address(self, address: str) -> str:
        """
        Processa un indirizzo (cripta/decripta).
        
        Args:
            address: Indirizzo da processare
            
        Returns:
            Indirizzo processato
            
        Notes:
            - Controlla prima la cache
            - Valida l'indirizzo
            - Cripta/decripta usando Fernet
            - Aggiorna la cache con il risultato
        """
        try:
            # Se stiamo decrittando, assumiamo che l'input sia già stato validato durante la crittografia
            if not self._is_encrypting:
                logging.debug(f"Decryption mode: returning unmodified address {address}")
                return address
            
            # Valida solo se stiamo crittografando
            if not self._validate_address(address):
                logging.warning(f"Invalid address format for encryption: {address}")
                return addres
            
            # Prima cerca nella cache
            try:
                cached_value = self._address_map.get(address)
                if cached_value is not None:
                    logging.debug(f"Address {address} retrieved from cache")
                    return cached_value
            except AddressNotFoundError:
                pass  # Se non trovato in cache, procedi con la crittografia
            
            # Processa l'indirizzo
            try:
                if self._is_encrypting:
                    processed = self._fernet.encrypt(address.encode()).decode()
                else:
                    processed = self._fernet.decrypt(address.encode()).decode()
                
                # Salva il risultato nella cache (sia per encrypt che decrypt)
                self._address_map.set(address, processed)
                logging.debug(f"Address {address} {'encrypted' if self._is_encrypting else 'decrypted'} and cached")
                return processed
                
            except Exception as e:
                logging.error(f"Unable to {'encrypt' if self._is_encrypting else 'decrypt'} IP address: {address}. Error: {str(e)}")
                return address
                
        except Exception as e:
            logging.warning(f"Unable to process address: {address}. Error: {str(e)}")
            return address

class IPCryptographer(BaseAddressCryptographer):
    """
    Gestisce la crittografia/decrittografia degli indirizzi IP.
    
    Estende BaseAddressCryptographer con:
    - Validazione specifica per indirizzi IP
    - Gestione di indirizzi IPv4 e IPv6
    """
    def _validate_address(self, ip: str) -> bool:
        """
        Valida un indirizzo IP.
        
        Args:
            ip: Indirizzo IP da validare
            
        Returns:
            True se è un IP valido e siamo in modalità crittografia,
            True se siamo in decrittografia (assumiamo input valido),
            False altrimenti
        """
        # In decrittazione, accettiamo l'input senza validazione
        if not self._is_encrypting:
            return True
        
        try:
            return Validator.is_valid_ip(ip)
        except Exception as e:
            logging.warning(f"Error validating IP address: {ip}. Error: {str(e)}")
            return False

class MACCryptographer(BaseAddressCryptographer):
    """
    Gestisce la crittografia/decrittografia degli indirizzi MAC.
    
    Estende BaseAddressCryptographer con:
    - Validazione specifica per indirizzi MAC
    - Supporto per diversi formati di MAC address (: o -)
    """
    def _validate_address(self, mac: str) -> bool:
        """
        Valida un indirizzo MAC.
        
        Args:
            mac: Indirizzo MAC da validare
            
        Returns:
            True se è un MAC valido e siamo in modalità crittografia,
            True se siamo in decrittografia (assumiamo input valido),
            False altrimenti
        """
        if not self._is_encrypting:
            return True
        
        try:
            return Validator.is_valid_mac(mac)
        except Exception as e:
            logging.warning(f"Error validating MAC address: {mac}. Error: {str(e)}")
            return False


class PacketCryptographer:
    """
    Gestisce la crittografia/decrittografia parallela dei pacchetti.
    
    Questa classe coordina:
    - Il processing parallelo dei pacchetti tramite thread pool
    - La gestione dei batch e dei retry automatici
    - Il monitoraggio del progresso e degli errori
    - La scrittura thread-safe dei risultati
    
    Il processing continua finché tutti i pacchetti sono stati processati
    con successo o fino a quando non si verifica un errore critico.
    
    Notes:
        - Usa ThreadPoolExecutor per una gestione efficiente dei thread
        - Implementa retry automatici per i pacchetti falliti
        - Garantisce che tutti i pacchetti vengano processati
    """
    
    def __init__(self, input_path: str, output_path: str, num_threads: int,
                 encryption_key: bytes, is_encrypting: bool):
        """
        Inizializza il cryptographer.
        
        Args:
            input_file: Path del file pcap di input
            output_file: Path dove salvare il file pcap processato
            num_threads: Numero di thread nel pool
            encryption_key: Chiave di crittografia/decrittografia
            is_encrypting: True per crittografia, False per decrittografia
        """
        self.input_path = input_path
        self.output_path = output_path
        self.encryption_key = encryption_key
        self.is_encrypting = is_encrypting
        
        # Thread Pool setup
        self.thread_pool = ThreadPoolExecutor(
            max_workers=num_threads,
            thread_name_prefix="CryptoWorker"
        )
        self.completion_futures: List[Future] = []
        
        # Inizializza cryptographers
        num_shards = num_threads * 2  # Sharding ottimale basato sul numero di thread
        self.fernet = Fernet(encryption_key)
        self.ip_cryptographer = IPCryptographer(self.fernet, is_encrypting, num_shards)
        self.mac_cryptographer = MACCryptographer(self.fernet, is_encrypting, num_shards)
        
        # Batch processing
        self.batch_processor = BatchProcessor()
        self.stats = ProcessingStats()
        
        # Lock e controlli
        self.processing_lock = threading.Lock()
        self.output_lock = threading.Lock()
        self.should_stop = threading.Event()
        
        # Error tracking
        self.error_thresholds = {
            'critical': 100,  # Errori che richiedono stop immediato
            'major': 500,     # Errori che potrebbero compromettere i risultati
            'minor': 1000     # Errori non critici
        }
        self.error_counts: DefaultDict[str, int] = defaultdict(int)
        self.error_lock = threading.Lock()

    def handle_error(self, error_type: str, error: Exception) -> None:
        """
        Gestisce gli errori in base alla loro gravità.
        
        Args:
            error_type: Tipo di errore ('critical', 'major', 'minor')
            error: L'eccezione verificatasi
        
        Raises:
            ProcessingError: Se viene superata la soglia di errori
        """
        with self.error_lock:
            self.error_counts[error_type] += 1
            if self.error_counts[error_type] >= self.error_thresholds[error_type]:
                self.should_stop.set()
                raise ProcessingError(f"Too many {error_type} errors: {error}")
                
            if self.error_counts[error_type] % 100 == 0:
                logging.warning(f"Accumulated {self.error_counts[error_type]} {error_type} errors")

    def process_packet(self, packet: Packet) -> Tuple[bool, Optional[Packet]]:
        """
        Processa un singolo pacchetto.
        
        Args:
            packet: Il pacchetto da processare
            
        Returns:
            Tuple[bool, Optional[Packet]]: (successo, pacchetto_processato)
        """
        try:
            #Crea una copia del pacchetto prima di modificarlo
            new_packet = packet.copy()
            if IP in packet:
                logging.info(f"Processing IP src: {packet[IP].src}, dst: {packet[IP].dst}")
                new_packet[IP].src = self.ip_cryptographer.process_address(packet[IP].src)
                new_packet[IP].dst = self.ip_cryptographer.process_address(packet[IP].dst)
                logging.info(f"Processed IP src: {new_packet[IP].src}, dst: {new_packet[IP].dst}")
            if Ether in packet:
                logging.info(f"Processing MAC src: {packet[Ether].src}, dst: {packet[Ether].dst}")
                new_packet[Ether].src = self.mac_cryptographer.process_address(packet[Ether].src)
                new_packet[Ether].dst = self.mac_cryptographer.process_address(packet[Ether].dst)
                logging.info(f"Processed MAC src: {new_packet[Ether].src}, dst: {new_packet[Ether].dst}")
                
            packet=new_packet
            return True, packet
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
            self.handle_error('major', e)
            return False, None

    def _process_batch(self, batch: List[Packet]) -> BatchResult:
        """
        Processa un batch di pacchetti.
        
        Args:
            batch: Lista di pacchetti da processare
            
        Returns:
            BatchResult con i risultati del processing
            
        Notes:
            - Traccia tempo di processing
            - Gestisce errori per singolo pacchetto
            - Aggiorna progress tracking
        """
        start_time = time.time()
        processed_packets = []
        failed_packets = []
        errors = []
        
        for packet in batch:
            if self.should_stop.is_set():
                break
                
            try:
                success, processed_packet = self.process_packet(packet)
                if success:
                    processed_packets.append(processed_packet)
                    with self.processing_lock:
                        self.stats.processed_packets += 1
                        if self.stats.processed_packets % 1000 == 0:
                            progress = (self.stats.processed_packets / self.stats.total_packets) * 100
                            logging.info(f"Progress: {progress:.2f}% ({self.stats.processed_packets}/{self.stats.total_packets})")
                else:
                    failed_packets.append(packet)
                    errors.append(Exception("Packet processing failed"))
                    self.handle_error('minor', Exception("Packet processing failed"))
                    
            except Exception as e:
                failed_packets.append(packet)
                errors.append(e)
                self.handle_error('major', e)
        
        return BatchResult(processed_packets, failed_packets, errors, time.time() - start_time)

    def _write_batch_results(self, batch_result: BatchResult) -> None:
        """
        Scrive i risultati del batch su file in modo thread-safe.
        
        Args:
            batch_result: Risultati del batch da scrivere
            
        Notes:
            - Gestisce directory relative al path di anonymizer.py
            - In fase di criptazione scrive in FileCriptati
            - In fase di decriptazione scrive in FileDecriptati
        """
        if not batch_result.processed_packets:
            return
            
        try:
            # Scrittura thread-safe dei pacchetti
            with self.output_lock:
                try:
                    packets_to_write = []
                    
                    # Prepara i pacchetti da scrivere
                    for packet in batch_result.processed_packets:
                        try:
                            if self.is_encrypting:
                                packets_to_write.append(packet)
                            else:
                                # Validazione per pacchetti decriptati
                                is_valid = True
                                if IP in packet:
                                    if not (Validator.is_valid_ip(packet[IP].src) and 
                                        Validator.is_valid_ip(packet[IP].dst)):
                                        logging.warning(f"Invalid decrypted IP address found. "
                                                    f"Src: {packet[IP].src}, Dst: {packet[IP].dst}")
                                        is_valid = False
                                
                                if Ether in packet:
                                    if not (Validator.is_valid_mac(packet[Ether].src) and 
                                        Validator.is_valid_mac(packet[Ether].dst)):
                                        logging.warning(f"Invalid decrypted MAC address found. "
                                                    f"Src: {packet[Ether].src}, Dst: {packet[Ether].dst}")
                                        is_valid = False
                                
                                if is_valid:
                                    packets_to_write.append(packet)
                                else:
                                    logging.error("Skipping packet with invalid decrypted addresses")
                                    
                        except Exception as e:
                            logging.error(f"Error processing packet for writing: {e}")
                            continue

                    if packets_to_write:
                        wrpcap(
                            filename=output_path,
                            pkt=packets_to_write,
                            append=True
                        )
                        
                        if not os.path.exists(self.output_path):
                            raise IOError(f"Failed to write to output file: {self.output_path}")
                        
                        operation = "encrypted" if self.is_encrypting else "decrypted"
                        logging.info(
                            f"Successfully wrote {len(packets_to_write)} {operation} "
                            f"packets to {self.output_path}"
                        )

                except Exception as e:
                    logging.error(f"Error during packet writing: {e}")
                    self.handle_error('critical', e)
                    raise

        except Exception as e:
            logging.error(f"Critical error in batch writing: {e}")
            self.handle_error('critical', e)
            raise
        
    def run(self) -> None:
        """
        Esegue il processing completo del file pcap.
        
        Flow:
        1. Legge il file pcap
        2. Raggruppa pacchetti in batch
        3. Processa i batch in parallelo
        4. Riprova con i pacchetti falliti
        5. Continua finché tutti i pacchetti sono processati
        """
        try:
            logging.info(f"{'Encrypting' if self.is_encrypting else 'Decrypting'} packets...")
            
            failed_packets = []  # Lista per pacchetti falliti
            
            # Primo passaggio: processo normale
            with PcapReader(self.input_path) as reader:
                for packet in reader:
                    if self.should_stop.is_set():
                        break
                    self.stats.total_packets += 1
                    
                    if completed_batch := self.batch_processor.add_packet(packet):
                        future = self.thread_pool.submit(self._process_batch, completed_batch)
                        result = future.result()
                        failed_packets.extend(result.failed_packets)
                        self._write_batch_results(result)
            
            # Processo gli ultimi pacchetti rimasti
            remaining = self.batch_processor.get_remaining()
            if remaining:
                future = self.thread_pool.submit(self._process_batch, remaining)
                result = future.result()
                failed_packets.extend(result.failed_packets)
                self._write_batch_results(result)
            
            # Retry pacchetti falliti finché necessario
            while failed_packets:
                self.stats.retry_count += 1
                logging.info(f"Retry attempt #{self.stats.retry_count} for {len(failed_packets)} failed packets...")
                
                # Uso batch più piccoli per i retry
                retry_batch_size = min(100, len(failed_packets))
                new_failed_packets = []
                
                for i in range(0, len(failed_packets), retry_batch_size):
                    retry_batch = failed_packets[i:i + retry_batch_size]
                    future = self.thread_pool.submit(self._process_batch, retry_batch)
                    result = future.result()
                    self._write_batch_results(result)
                    
                    if result.failed_packets:
                        new_failed_packets.extend(result.failed_packets)
                
                failed_packets = new_failed_packets
                
                if failed_packets:
                    logging.warning(f"Still {len(failed_packets)} packets failed after retry #{self.stats.retry_count}")
                    time.sleep(self.stats.retry_count * 0.1)  # Attesa incrementale
            
            logging.info("All packets processed successfully!")
            
        except Exception as e:
            logging.error(f"Fatal error during processing: {e}")
            self.should_stop.set()
            raise
        finally:
            self.cleanup_resources()

    def cleanup_resources(self) -> None:
        """
        Pulisce le risorse e chiude il thread pool.
        """
        try:
            self.thread_pool.shutdown(wait=True)
            
            if self.error_counts:
                logging.warning("Error summary:")
                for error_type, count in self.error_counts.items():
                    logging.warning(f"{error_type} errors: {count}")
                    
        except Exception as e:
            logging.error(f"Error during cleanup: {e}")
            raise


#def generate_key_filename(input_file: str) -> str:
#    """
#    Genera il nome del file per la chiave di crittografia.
#    
#    Args:
#        input_file: Path del file pcap di input
#        
#    Returns:
#        str: Nome del file per la chiave
#    """
#    base_name = os.path.basename(input_file)
#    return os.path.join("chiavi", f"encryption_key_{base_name}.txt")

def generate_key_filename(input_file: str) -> str:
    """Genera il nome del file per la chiave di crittografia."""
    return ProjectDirectories.get_key_path(os.path.basename(input_file))

# def load_encryption_key(input_file: str, is_decrypting: bool) -> bytes:
#     """
#     Carica o genera la chiave di crittografia.
    
#     Args:
#         input_file: Path del file pcap
#         is_decrypting: True se in modalità decrittazione
        
#     Returns:
#         bytes: Chiave di crittografia
        
#     Raises:
#         FileExistsError: Se il file chiave esiste in modalità crittografia
#         FileNotFoundError: Se il file chiave non esiste in modalità decrittografia
#         RuntimeError: Per altri errori di gestione chiave
#     """
#     key_filename = generate_key_filename(input_file)
    
#     try:
#         if not is_decrypting:  # MODALITA CRITTOGRAFIA
#             if os.path.exists(key_filename):
#                 raise FileExistsError(
#                     f"Key file {key_filename} already exists. "
#                     "Please backup or remove it first."
#                 )
            
#             key = Fernet.generate_key()
#             # Crea file temporaneo (Se il processo si interrompe durante la scrittura del file temporaneo, il file chiave originale (se esiste) non viene compromesso)
#             with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
#                 temp_file.write(key)
#                 temp_path = temp_file.name
            
#             #os.chmod(temp_path, 0o600)  # Permessi ristretti
#             shutil.move(temp_path, key_filename)
#             return key
        
#         else:  # MODALITA DECRITTAZIONE
#             if not os.path.exists(key_filename):
#                 raise FileNotFoundError(
#                     f"Encryption key file {key_filename} not found"
#                 )
            
#             # Controlla i permessi del file
#             #current_permissions = os.stat(key_filename).st_mode & 0o777
#             #if current_permissions != 0o600:
#                 #logging.warning(
#                     #f"Insecure key file permissions: {oct(current_permissions)}"
#                 #)
            
#             # Legge e valida la chiave    
#             with open(key_filename, 'rb') as key_file:
#                 key = key_file.read()
#                 if len(key) != 32:
#                     raise ValueError("Invalid key length")
#                 try:
#                     Fernet(key)  # Valida il formato della chiave
#                 except Exception as e:
#                     raise ValueError(f"Invalid key format: {e}")
#             return key
            
#     except (IOError, OSError) as e:
#         raise RuntimeError(f"Error handling encryption key: {e}")

def load_encryption_key(input_file: str, is_decrypting: bool) -> bytes:
    """Carica o genera la chiave di crittografia."""
    key_filename = generate_key_filename(input_file)
    
    try:
        if not is_decrypting:
            if os.path.exists(key_filename):
                raise FileExistsError(
                    f"Key file {key_filename} already exists. Please backup or remove it first."
                )
            
            key = Fernet.generate_key()
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
                temp_file.write(key)
                temp_path = temp_file.name
            
            shutil.move(temp_path, key_filename)
            return key
        
        else:
            if not os.path.exists(key_filename):
                raise FileNotFoundError(f"Encryption key file {key_filename} not found")
            
            with open(key_filename, 'rb') as key_file:
                key = key_file.read()
                if len(key) != 32:
                    raise ValueError("Invalid key length")
                Fernet(key)  # Valida il formato della chiave
                return key
            
    except (IOError, OSError) as e:
        raise RuntimeError(f"Error handling encryption key: {e}")
    
def validate_pcap_file(filepath: str) -> bool:
    """
    Verifica che il file sia un pcap valido.
    
    Args:
        filepath: Path del file da validare
        
    Returns:
        bool: True se il file è valido
        
    Raises:
        ValueError: Se il file non è un pcap valido
    """
    try:
        if not Validator.validate_file_extension(filepath):
            raise ValueError(f"Unsupported file extension")
        with PcapReader(filepath) as reader:
            next(reader)
        return True
    except Exception as e:
        raise ValueError(f"Invalid PCAP file: {e}")

def main(input_path: str, output_path: str, num_threads: int, 
         is_encrypting: bool, provided_key: Optional[str] = None) -> None:
    """
    Funzione principale per la gestione della crittografia/decrittografia.
    
    Args:
        input_file: Path del file pcap di input
        output_file: Path del file di output
        num_threads: Numero di thread da utilizzare
        is_encrypting: True per crittografia, False per decrittografia
        provided_key: Chiave opzionale fornita dall'utente
        
    Raises:
        FileNotFoundError: Se il file di input non esiste
        ValueError: Se i parametri non sono validi
    """
    # Validazione struttura directory
    ProjectDirectories.verify_directory_structure()
    
    #estrai nomi di file dai percorsi
    input_file = os.path.basename(input_path)
    output_file = os.path.basename(output_path)
    
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file {input_file} not found")
        
    if num_threads < 1:
        raise ValueError("Number of threads must be positive")
 
    # Gestione chiave
    if provided_key:
        try:
            encryption_key = provided_key.encode()
            Fernet(encryption_key)  # Valida formato chiave
        except Exception:
            raise ValueError("Invalid encryption key provided")
    else:
        encryption_key = load_encryption_key(input_file, not is_encrypting)

    # Processa il file
    start_time = time.time()
    operation = "encryption" if is_encrypting else "decryption"
    logging.info(f"Starting packet {operation} with {num_threads} threads...")
    
    try:
        cryptographer = PacketCryptographer(
            input_path=input_path,
            output_path=output_path,
            num_threads=num_threads,
            encryption_key=encryption_key,
            is_encrypting=is_encrypting
        )
        cryptographer.run()

        end_time = time.time()
        logging.info(
            f"{operation.capitalize()} completed in {end_time - start_time:.2f} seconds"
        )
        logging.info(f"Processed packets written to {output_file}")
        
    except ProcessingError as e:
        logging.error(f"Processing error: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        raise

if __name__ == "__main__":
    # Configurazione logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)

    # Parse argomenti linea comando
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt a Wireshark capture file."
    )
    parser.add_argument(
        "input_file",
        help="Input Wireshark capture file"
    )
    parser.add_argument(
        "--decrypt",
        action="store_true",
        help="Decrypt the capture file instead of encrypting"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=4,
        help="Number of worker threads (default: 4)"
    )
    
    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument(
        "--key",
        help="Direct encryption/decryption key (base64 encoded)"
    )

    args = parser.parse_args()

    try:
        # Determina modalità crittografia/decrittazione
        is_encrypting = not args.decrypt  # True se crittografia, False se decrittazione
        
        input_path = ProjectDirectories.get_input_path(args.input_file)
        Validator.validate_pcap_file(input_path)
        
        output_path = ProjectDirectories.get_output_path(
            os.path.basename(args.input_file),
            is_encrypting
        )  # Sarà gestito in main()
        #print(f"Cercando il file in: {os.path.abspath(input_file)}")
        #print("Files nella cartella:", os.listdir("FileDaCrittografare"))
        #print("Permessi di lettura:", os.access(input_file, os.R_OK))
        
        # Verifica che la chiave sia fornita solo in decrittazione
        if args.key and is_encrypting:
            logging.error("Key parameter can only be used in decryption mode")
            exit(1)
        
        # Se viene fornita una chiave diretta in modalità decrypt, la passa a main()
        encryption_key = args.key if (args.key and not is_encrypting) else None
        
        # Esegue il processing
        main(input_path, output_path, args.threads, is_encrypting, encryption_key)
        
    except FileNotFoundError as e:
        logging.error(str(e))
        exit(1)
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        exit(1)
