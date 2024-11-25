import hashlib
import os
import argparse
import tempfile
import shutil
from scapy.all import * # type: ignore
from scapy.utils import PcapReader # type: ignore
import threading
from threading import RLock  
from queue import Queue, Empty
import time
from typing import Dict, Optional, List, Tuple, DefaultDict,OrderedDict as OrderedDictType
from collections import OrderedDict
import logging
import ipaddress
import re
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, Future
from collections import defaultdict
from dataclasses import dataclass
from abc import ABC, abstractmethod
from Crypto.Cipher import AES # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
from Crypto.Util.Padding import pad, unpad # type: ignore
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
    def get_input_path(cls, filename: str,is_decrypting: bool) -> str:
        """
        Costruisce il percorso completo per un file di input.
        In modalità decrypt, cerca il file nella cartella FileCriptati.
        
        Args:
            filename: Nome del file
            is_decrypting: True se in modalità decrypt
            
        Returns:
            str: Percorso completo nel formato appropriato in base alla modalità
        """
        if is_decrypting:
            return os.path.join(cls.ENCRYPTED_DIR, filename)
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

class AESAddressCrypto:
    """
    Gestisce la crittografia/decrittografia AES degli indirizzi.
    Cripta solo i bytes necessari per identificare univocamente un indirizzo.
    """
    def __init__(self, key: bytes):
        """
        Inizializza il cryptographer AES.
        
        Args:
            key: Chiave AES a 16 byte (128 bit)
        """
        if len(key) != 16:  # AES-128
            raise ValueError("Key must be exactly 16 bytes for AES-128")
        
        hash_obj = hashlib.sha256(key)
        self.ip_key = hash_obj.digest()[:16]
        self.mac_key = hash_obj.digest()[16:32]
        self.block_size = AES.block_size

    
    def encrypt_ip(self, ip: str) -> str:
        """
        Critta l'intero indirizzo IP in modo reversibile.
        """
        if not ip:
            return ip
            
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return ip
            
            # Usa la chiave specifica per IP
            cipher = AES.new(self.ip_key, AES.MODE_ECB)  # Usa self.ip_key invece di self.key

            # Converti l'IP in un numero a 32 bit
            ip_num = sum(int(parts[i]) << (24 - 8 * i) for i in range(4))
            
            # Convertiamo il numero in 4 bytes
            data = ip_num.to_bytes(4, byteorder='big')
            # Padding per arrivare a 16 bytes (blocco AES)
            padded = pad(data, 16)
            encrypted = cipher.encrypt(padded)
            
            # Prendi i primi 4 bytes e convertili in nuovo IP
            enc_num = int.from_bytes(encrypted[:4], byteorder='big')
            
            # Costruisci il nuovo IP
            new_ip = []
            for i in range(4):
                new_ip.insert(0, str(enc_num & 255))
                enc_num >>= 8
                
            return '.'.join(new_ip)
            
        except Exception as e:
            logging.error(f"Error encrypting IP {ip}: {e}")
            return ip

    def decrypt_ip(self, encrypted_ip: str) -> str:
        """
        Decripta l'indirizzo IP tornando all'originale.
        """
        try:
            parts = encrypted_ip.split('.')
            if len(parts) != 4:
                return encrypted_ip
                
            # Decritta usando la stessa modalità
            cipher = AES.new(self.ip_key, AES.MODE_ECB)
            # Converti l'IP crittato in numero
            ip_num = sum(int(parts[i]) << (24 - 8 * i) for i in range(4))
            # Convertiamo il numero in 4 bytes
            data = ip_num.to_bytes(4, byteorder='big')
            # Padding per arrivare a 16 bytes
            padded = pad(data, 16)
            decrypted = cipher.decrypt(padded)
            
            # Prendi i primi 4 bytes e convertili in IP originale
            dec_num = int.from_bytes(decrypted[:4], byteorder='big')
            
            # Ricostruisci l'IP originale
            original_ip = []
            for i in range(4):
                original_ip.insert(0, str(dec_num & 255))
                dec_num >>= 8
                
            return '.'.join(original_ip)
            
        except Exception as e:
            logging.error(f"Error decrypting IP {encrypted_ip}: {e}")
            return encrypted_ip

    def encrypt_mac(self, mac: str) -> str:
        """
        Critta l'indirizzo MAC in modo reversibile usando AES in modalità ECB.
        La modalità ECB garantisce che lo stesso MAC produrrà sempre lo stesso output
        con la stessa chiave, permettendo una corretta decrittazione.
        """
        if not mac:
            return mac
            
        try:
            parts = mac.split(':')
            if len(parts) != 6:
                return mac
                
            # Converti il MAC in numero a 48 bit
            mac_num = int(''.join(parts), 16)
            
            # Critta il numero
            cipher = AES.new(self.mac_key, AES.MODE_ECB)
            data = mac_num.to_bytes(6, byteorder='big')
            padded = pad(data, 16)
            encrypted = cipher.encrypt(padded)
            
            # Prendi i primi 6 bytes e convertili in nuovo MAC
            enc_num = int.from_bytes(encrypted[:6], byteorder='big')
            
            # Costruisci il nuovo MAC
            new_mac = []
            for i in range(6):
                new_mac.insert(0, f"{enc_num & 255:02x}")
                enc_num >>= 8
                
            return ':'.join(new_mac)
            
        except Exception as e:
            logging.error(f"Error encrypting MAC {mac}: {e}")
            return mac

    def decrypt_mac(self, encrypted_mac: str) -> str:
        """
        Decritta il MAC tornando all'originale.
        La modalità ECB garantisce che lo stesso input crittato 
        produrrà sempre lo stesso output con la stessa chiave.
        """
        try:
            parts = encrypted_mac.split(':')
            if len(parts) != 6:
                return encrypted_mac
                
            # Decritta
            cipher = AES.new(self.mac_key, AES.MODE_ECB)
            # Converti il MAC crittato in numero
            mac_num = int(''.join(parts), 16)
            data = mac_num.to_bytes(6, byteorder='big')
            padded = pad(data, 16)
            decrypted = cipher.decrypt(padded)
            
            # Ricostruisci il MAC originale
            dec_num = int.from_bytes(decrypted[:6], byteorder='big')
            
            # Formato MAC originale
            original_mac = []
            for i in range(6):
                original_mac.insert(0, f"{dec_num & 255:02x}")
                dec_num >>= 8
                
            return ':'.join(original_mac)
            
        except Exception as e:
            logging.error(f"Error decrypting MAC {encrypted_mac}: {e}")
            return encrypted_mac

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
        """Verifica se l'indirizzo MAC è valido."""
        if not address:
            logging.info(f"Validation failed for empty MAC address")
            return False
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$')
        return bool(mac_pattern.match(address))
    
    @staticmethod
    def is_valid_ip(address: str) -> bool:
        """Verifica se l'indirizzo IP è valido."""
        if not address:
            logging.info(f"Validation failed for empty IP address")
            return False
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
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

@dataclass
class Shard:
    """
    Rappresenta uno shard con il suo dizionario e lock associato.
    Raggruppa logicamente i dati con il loro meccanismo di sincronizzazione.
    """
    data: Dict[str, str]
    lock: RLock

class NetworkShardedDict:
    """
    Gestisce gli indirizzi con sharding e caching LRU.
    
    Questa classe implementa:
    - Sharding degli indirizzi per ottimizzare l'accesso concorrente
    - Cache LRU per gli indirizzi più frequentemente acceduti
    - Accesso thread-safe ai dati
    
    Attributes:
        
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
        if num_shards < 1:
            raise ValueError("Number of shards must be positive")
        
        self._shards: List[Shard] = [Shard(data={},lock=RLock()) for _ in range (num_shards)]
        self._hot_cache: OrderedDictType[str, Tuple[int, str]] = OrderedDict()
        self._max_cache_entries: int= max_cache_entries
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
                self._hot_cache.popitem(last=False)
            
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
        if not address:
            raise ValueError("Address cannot be empty")
        
        try:
            # Prima controlliamo la cache
            with self._hot_cache_lock:
                if cached := self._hot_cache.get(address):
                    self._hot_cache.move_to_end(address)
                    return cached[1]
            
            # Cache miss, cerca nello shard
            shard_idx = self._get_shard_index(address)
            shard= self._shards[shard_idx]
            
            with shard.lock:
                with self._hot_cache_lock:
                    #Ricontrolliamo cache dopo aver acquisito lock
                    if cached := self._hot_cache.get(address):
                        self._hot_cache.move_to_end(address)
                        logging.info(f"Cache hit for address {address}")
                        return cached[1]
                    #Non in cache cerchiamo nello shard
                    if value:= self._shards[shard_idx].data.get(address):
                        self._update_cache(address,shard_idx,value)
                        return value
            #Se arriviamo qui indirizzo non esiste    
            raise AddressNotFoundError(f"Address {address} not found")
        
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
        if not address:
            raise ValueError("Address cannot be empty")
        
        if not isinstance(value, str):
            raise ValueError("Value must be a string")
        try:
            shard_idx = self._get_shard_index(address)
            shard = self._shards[shard_idx]
            # Acquisiamo i lock in ordine consistente per evitare deadlock
            with shard.lock:
                with self._hot_cache_lock:
                    #Aggiorno entrambe le strutture mentre ho i lock
                    shard.data[address] = value
                    self._update_cache(address,shard_idx,value)
                    logging.info(f"Set address {address} in shard {shard_idx} with value: {value[:50]}")
                
        except Exception as e:
            logging.error(f"Error setting value for {address}: {e}")
            raise

class BaseAddressCryptographer(ABC):
    """
    Classe base astratta per la crittografia/decrittografia degli indirizzi.
    """
    def __init__(self, key: bytes , is_encrypting: bool, num_shards: int):
        """
        Inizializza il cryptographer base.
        
        Args:
            key: Chiave AES per la crittografia
            is_encrypting: True per crittografia, False per decrittografia
            num_shards: Numero di shards per il dizionario degli indirizzi
        """
        self._address_map = NetworkShardedDict(num_shards=num_shards)
        self._aes = AESAddressCrypto(key)
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
            str: Indirizzo processato
        """
        try:
            # Prima verifica che l'indirizzo non sia vuoto
            if not address:
                logging.debug("Empty address received")
                return address
            
            if self._is_encrypting:
                # In modalità crittografia, valida l'indirizzo originale
                if not self._validate_address(address):
                    logging.debug(f"Skipping invalid address format: {address}")
                    return address
                    
                # Dopo la validazione, controlla la cache
                try:
                    cached_value = self._address_map.get(address)
                    if cached_value is not None:
                        logging.debug(f"Cache hit for address: {address}")
                        return cached_value
                except AddressNotFoundError:
                    pass
                
                # Se non in cache, cripta e salva
                processed = self._encrypt_address(address)
                self._address_map.set(address, processed)
                return processed
                
            else:
                # In modalità decrittazione
                try:
                    # Prima controlla la cache
                    cached_value = self._address_map.get(address)
                    if cached_value is not None:
                        logging.debug(f"Cache hit for encrypted address: {address}")
                        return cached_value
                except AddressNotFoundError:
                    pass
                
                # Se non in cache, decripta
                try:
                    processed = self._decrypt_address(address)
                    # Valida l'indirizzo decrittato
                    if not self._validate_address(processed):
                        logging.warning(f"Decrypted address is invalid: {processed}")
                        return address
                        
                    # Se valido, salva in cache e restituisci
                    self._address_map.set(address, processed)
                    return processed
                    
                except Exception as e:
                    logging.warning(f"Failed to decrypt address {address}: {e}")
                    return address
                    
        except Exception as e:
            logging.warning(f"Unable to process address: {address}. Error: {str(e)}")
            return address

class IPCryptographer(BaseAddressCryptographer):
    """
    Gestisce la crittografia/decrittografia degli indirizzi IP.
    """
    def _validate_address(self, address: str) -> bool:
        """
        Valida un indirizzo IP.
        
        Args:
            address: Indirizzo IP da validare
            
        Returns:
            bool: True se è un IP valido, False altrimenti
        """
        try:
            return Validator.is_valid_ip(address)
        except Exception as e:
            logging.warning(f"Error validating IP address: {address}. Error: {str(e)}")
            return False

    def _encrypt_address(self, address: str) -> str:
        """
        Cripta un indirizzo IP. Cripta solo gli ultimi due ottetti.
        
        Args:
            address: Indirizzo IP da crittare
            
        Returns:
            str: Indirizzo IP con gli ultimi due ottetti crittati
        """
        try:
            return self._aes.encrypt_ip(address)
        except Exception as e:
            logging.error(f"Error encrypting IP address: {address}. Error: {str(e)}")
            return address

    def _decrypt_address(self, address: str) -> str:
        """
        Decripta un indirizzo IP.
        
        Args:
            address: Indirizzo IP da decrittare
            
        Returns:
            str: Indirizzo IP decrittato
        """
        try:
            return self._aes.decrypt_ip(address)
        except Exception as e:
            logging.error(f"Error decrypting IP address: {address}. Error: {str(e)}")
            return address

class MACCryptographer(BaseAddressCryptographer):
    """
    Gestisce la crittografia/decrittografia degli indirizzi MAC.
    """
    def _validate_address(self, address: str) -> bool:
        """
        Valida un indirizzo MAC.
        
        Args:
            address: Indirizzo MAC da validare
            
        Returns:
            bool: True se è un MAC valido, False altrimenti
        """
        try:
            return Validator.is_valid_mac(address)
        except Exception as e:
            logging.warning(f"Error validating MAC address: {address}. Error: {str(e)}")
            return False

    def _encrypt_address(self, address: str) -> str:
        """
        Cripta un indirizzo MAC. Cripta solo gli ultimi tre ottetti.
        
        Args:
            address: Indirizzo MAC da crittare
            
        Returns:
            str: Indirizzo MAC con gli ultimi tre ottetti crittati
        """
        try:
            return self._aes.encrypt_mac(address)
        except Exception as e:
            logging.error(f"Error encrypting MAC address: {address}. Error: {str(e)}")
            return address

    def _decrypt_address(self, address: str) -> str:
        """
        Decripta un indirizzo MAC.
        
        Args:
            address: Indirizzo MAC da decrittare
            
        Returns:
            str: Indirizzo MAC decrittato
        """
        try:
            return self._aes.decrypt_mac(address)
        except Exception as e:
            logging.error(f"Error decrypting MAC address: {address}. Error: {str(e)}")
            return address

@contextmanager
def managed_pcap_writer(output_path: str, is_encrypting: bool):
    """
    Context manager per la gestione sicura della scrittura di file PCAP.
    Se il file di output esiste già, chiede all'utente se vuole sovrascriverlo.
    
    Args:
        output_path: Il percorso del file di output finale
        is_encrypting: True se stiamo crittando, False se decrittando
        
    Raises:
        SystemExit: Se l'utente sceglie di non sovrascrivere il file
        Exception: Per errori durante la gestione dei file
    """
    temp_path = f"{output_path}.tmp"
    operation = "encrypted" if is_encrypting else "decrypted"
    
    # Controllo preliminare dell'esistenza del file
    if os.path.exists(output_path):
        while True:
            print(f"\nA {operation} file already exists at:")
            print(f"'{output_path}'")
            response = input(f"Do you want to overwrite it? [y/n]: ").lower()
            if response in ['y', 'n']:
                if response == 'n':
                    print("\nOperation cancelled. No files were modified.")
                    logging.info("User chose not to overwrite existing file. Exiting.")
                    sys.exit(0)
                break
            print("\nPlease enter 'y' or 'n'")
            
    # Se l'utente ha scelto di sovrascrivere o il file non esisteva
    logging.info(f"Starting {operation} file creation at: {output_path}")
    
    try:
        # Assicurati che non ci siano file temporanei residui
        if os.path.exists(temp_path):
            os.remove(temp_path)
            logging.info(f"Removed existing temporary file: {temp_path}")
        
        yield temp_path
        
    finally:
        # Gestione del file temporaneo alla fine del blocco with
        if os.path.exists(temp_path):
            if sys.exc_info()[0] is None:  # Nessun errore durante l'esecuzione
                try:
                    # Se esiste un file di output precedente, rimuovilo
                    if os.path.exists(output_path):
                        os.remove(output_path)
                        logging.info(f"Removed existing file: {output_path}")
                    
                    # Sposta il file temporaneo nella destinazione finale
                    shutil.move(temp_path, output_path)
                    logging.info(f"Successfully created {operation} file: {output_path}")
                    
                except Exception as e:
                    # Se qualcosa va male durante la finalizzazione
                    logging.error(f"Error while finalizing {operation} file: {e}")
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                    raise
            else:
                # Se ci sono stati errori durante il processing
                logging.error(f"Processing failed, cleaning up temporary file")
                if os.path.exists(temp_path):
                    os.remove(temp_path)

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
        num_shards = num_threads * 2 # Sharding ottimale basato sul numero di thread
        self.ip_cryptographer = IPCryptographer(encryption_key, is_encrypting, num_shards)
        self.mac_cryptographer = MACCryptographer(encryption_key, is_encrypting, num_shards)
        
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
    
    def _initialize_output_file(self):
        """
        Inizializza il file di output vuoto.
        """
        try:
            # Crea un file PCAP vuoto con wrpcap
            wrpcap(self.output_path, [])
            logging.info(f"Initialized empty output file: {self.output_path}")
        except Exception as e:
            logging.error(f"Failed to initialize output file: {e}")
            raise

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
        """
        try:
            #Crea una copia del pacchetto prima di modificarlo
            new_packet = packet.copy()
            modified=False
            if IP in packet:
                old_src = new_packet[IP].src
                old_dst = new_packet[IP].dst
                new_src = self.ip_cryptographer.process_address(old_src)
                new_dst = self.ip_cryptographer.process_address(old_dst)

                if new_src != old_src or new_dst != old_dst:
                    new_packet[IP].src = new_src
                    new_packet[IP].dst = new_dst
                    modified = True
                    logging.debug(f"Modified IP addresses: {old_src}->{new_src}, {old_dst}->{new_dst}")
            if Ether in packet:
                old_src = new_packet[Ether].src
                old_dst = new_packet[Ether].dst
                new_src = self.mac_cryptographer.process_address(old_src)
                new_dst = self.mac_cryptographer.process_address(old_dst)
                
                if new_src != old_src or new_dst != old_dst:
                    new_packet[Ether].src = new_src
                    new_packet[Ether].dst = new_dst
                    modified = True
                    logging.debug(f"Modified MAC addresses: {old_src}->{new_src}, {old_dst}->{new_dst}")
                
            # Restituisci il pacchetto solo se è stato effettivamente modificato
            return modified, new_packet if modified else None
                
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
                        self.stats.processed_packets+=1
                        if self.stats.processed_packets % 1000 == 0:
                            progress = (self.stats.processed_packets/ self.stats.total_packets) * 100
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

    def _write_batch_results(self, batch_result: BatchResult,output_file: str) -> None:
        """
        Scrive i risultati del batch su file in modo thread-safe.
        
        Args:
            batch_result: Risultati del batch da scrivere
            output_file: Path del file su cui scrivere (può essere il file temporaneo)
         Notes:
            - In modalità context manager, output_file sarà il file .tmp
            - Il context manager si occuperà di rinominare/spostare il file nella posizione finale
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
                        if packet is not None and hasattr(packet, 'name') and packet.name == 'Ethernet':  # Skip None packets o pacchetti non Ethernet
                            try:
                                if self.is_encrypting:
                                    packets_to_write.append(packet)
                                else:
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
                                        
                            except Exception as e:
                                logging.error(f"Error processing packet for writing: {e}")
                                continue

                    if packets_to_write:
                        wrpcap(
                            output_file,
                            packets_to_write,
                            append=True
                        )
                        
                        if not os.path.exists(output_file):
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
            
            with managed_pcap_writer(self.output_path, self.is_encrypting) as temp_path:
                wrpcap(temp_path,[])
                failed_packets = [] #lista pacchetti falliti
                
            # Primo passaggio: processo normale
                with PcapReader(self.input_path) as reader:
                    for packet in reader:
                        if self.should_stop.is_set():
                            break
                        with self.processing_lock:
                            self.stats.total_packets += 1
                        
                        
                        if completed_batch := self.batch_processor.add_packet(packet):
                            future = self.thread_pool.submit(self._process_batch, completed_batch)
                            result = future.result()
                            failed_packets.extend(result.failed_packets)
                            #Passiamo temp_path alla scrittura
                            self._write_batch_results(result,temp_path)
                
                # Processo gli ultimi pacchetti rimasti
                remaining = self.batch_processor.get_remaining()
                if remaining:
                    future = self.thread_pool.submit(self._process_batch, remaining)
                    result = future.result()
                    failed_packets.extend(result.failed_packets)
                    self._write_batch_results(result,temp_path)
                
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
                        self._write_batch_results(result,temp_path)
                        
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

def generate_key_filename(input_file: str,is_decrypting: bool) -> str:
    """
    Genera il nome del file per la chiave di crittografia.
    In modalità decrypt rimuove il prefisso 'encrypted_' dal nome del file.
    
    Args:
        input_file: Nome del file di input
        is_decrypting: True se in modalità decrypt
    
    Returns:
        str: Path completo del file chiave
    """
    base_filename = os.path.basename(input_file)
    if is_decrypting and base_filename.startswith("encrypted_"):
        base_filename = base_filename[len("encrypted_"):]
    return ProjectDirectories.get_key_path(base_filename)


def load_encryption_key(input_file: str, is_decrypting: bool) -> bytes:
    """Carica o genera la chiave AES.
       In modalità criptazione, genera la chiave e sovrascrive il file se esiste.
       In modalità decriptazione, carica la chiave esistente."""
    key_filename = generate_key_filename(input_file,is_decrypting) 
    
    try:
        if not is_decrypting: #Modalità criptazione
            
            # Genera una chiave AES-128
            key = get_random_bytes(16)  # 16 bytes = 128 bit

            # Converti in Base64 per salvataggio leggibile
            key_b64 = base64.b64encode(key).decode('utf-8')
            # Salva in formato leggibile
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                temp_file.write(key_b64)
                temp_file.write('\n')  # Aggiungi newline per leggibilità
                temp_file.write(f'# Chiave AES-128 per il file: {input_file}\n')
                temp_file.write(f'# Generata il: {time.strftime("%Y-%m-%d %H:%M:%S")}\n')
                temp_file.write('# Usare questa chiave con --key per decriptare il file\n')
                temp_path = temp_file.name
            
            # Sovrascrive il file esistente se presente
            shutil.move(temp_path, key_filename)
            logging.info(f"{'Updated' if os.path.exists(key_filename) else 'Created'} encryption key file: {key_filename}")
            return key
        
        else: #Modalità decript
            if not os.path.exists(key_filename):
                raise FileNotFoundError(f"Encryption key file {key_filename} not found")
            
            with open(key_filename, 'r') as key_file:
                # Leggi solo la prima riga che contiene la chiave Base64
                key_b64 = key_file.readline().strip()
                
            try:
                # Converti da Base64 a bytes
                key = base64.b64decode(key_b64)
                if len(key) != 16:
                    raise ValueError("Invalid key length - must be 16 bytes for AES-128")
                return key
            except Exception as e:
                raise ValueError(f"Invalid key format: {e}")
                
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
        if is_encrypting:
            raise FileNotFoundError(f"Input file {input_file} not found in FileDaCrittografare directory")
        else:
            raise FileNotFoundError(f"Input file {input_file} not found in FileCriptati directory")
        
    if num_threads < 1:
        raise ValueError("Number of threads must be positive")
 
    # Gestione chiave AES
    if provided_key:
        try:
            # La chiave fornita deve essere in base64
            encryption_key = base64.b64decode(provided_key)
            if len(encryption_key) != 16:  # AES-128 richiede 16 byte
                raise ValueError("Invalid key length - must be 16 bytes for AES-128")
        except Exception:
            raise ValueError("Invalid encryption key provided - must be base64 encoded 16-byte key")
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
        
        input_path = ProjectDirectories.get_input_path(args.input_file, is_decrypting=not is_encrypting)
        Validator.validate_pcap_file(input_path)
        
        output_path = ProjectDirectories.get_output_path(
            os.path.basename(args.input_file),
            is_encrypting
        )
        
        # Verifica che la chiave sia fornita in base64 valido se specificata
        if args.key:
            try:
                decoded_key = base64.b64decode(args.key)
                if len(decoded_key) != 16:
                    raise ValueError("Decoded key must be exactly 16 bytes for AES-128")
            except Exception as e:
                logging.error(f"Invalid key format: {e}")
                logging.error("The key must be a base64 encoded string of 16 bytes")
                exit(1)
        
        # Se viene fornita una chiave diretta in modalità decrypt, la passa a main()
        encryption_key = args.key if args.key else None
        
        # Esegue il processing
        main(input_path, output_path, args.threads, is_encrypting, encryption_key)
        
    except FileNotFoundError as e:
        logging.error(str(e))
        exit(1)
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        exit(1)
