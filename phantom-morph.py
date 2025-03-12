import math
import re
import os
import sys
import logging
import argparse
import hashlib
import base64
import random
import string
import json
import time
import threading
import queue
import ipaddress
import subprocess
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Union, Optional, Any, Callable

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    pefile = None
    PEFILE_AVAILABLE = False

try:
    from transformers import pipeline
    MODEL_AVAILABLE = True
except ImportError:
    MODEL_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    Fernet = None

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
    from rich.syntax import Syntax
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    try:
        from colorama import init, Fore, Style
        init(autoreset=True)
        COLORAMA_AVAILABLE = True
    except ImportError:
        COLORAMA_AVAILABLE = False
        class Fore:
            RED = ""
            GREEN = ""
            BLUE = ""
            YELLOW = ""
            CYAN = ""
            MAGENTA = ""
            WHITE = ""
        class Style:
            BRIGHT = ""
            RESET_ALL = ""

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
log_handler = logging.StreamHandler()
log_handler.setFormatter(log_formatter)
logger = logging.getLogger("UltimateTool")
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)
logger.propagate = False

try:
    os.makedirs("logs", exist_ok=True)
    file_handler = logging.FileHandler(f"logs/ultimate_tool_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    file_handler.setFormatter(log_formatter)
    logger.addHandler(file_handler)
except Exception as e:
    logger.warning(f"Could not create log file: {e}")

VERSION = "2.0.0"
GITHUB_URL = "https://github.com/guilherme-moraiss"

DEFAULT_YARA_RULES = """
rule potential_shellcode
{
    strings:
        $s1 = { 31 c0 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50 53 89 e1 b0 0b cd 80 }
        $s2 = { 68 63 6d 64 00 }
        $s3 = { 68 65 78 65 00 }
    condition:
        any of them
}

rule suspicious_api_strings
{
    strings:
        $process1 = "CreateProcess" nocase
        $process2 = "ShellExecute" nocase
        $process3 = "WinExec" nocase
        $inject1 = "VirtualAlloc" nocase
        $inject2 = "WriteProcessMemory" nocase
        $inject3 = "CreateRemoteThread" nocase
        $registry1 = "RegCreateKey" nocase
        $registry2 = "RegSetValue" nocase
        $network1 = "WSASocket" nocase
        $network2 = "connect" nocase
        $network3 = "recv" nocase
        $network4 = "send" nocase
    condition:
        2 of them
}

rule potential_crypter
{
    strings:
        $enc1 = "Encrypt" nocase
        $enc2 = "Decrypt" nocase
        $enc3 = "AES" nocase
        $enc4 = "RC4" nocase
        $enc5 = "XOR" nocase
        $high_entropy = /[\x00-\xff]{100,}/
    condition:
        (2 of ($enc*)) or $high_entropy
}

rule suspicious_powershell
{
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "-enc" nocase
        $ps3 = "-encodedcommand" nocase
        $ps4 = "-nop" nocase
        $ps5 = "-windowstyle hidden" nocase
        $ps6 = "IEX" nocase
        $ps7 = "Invoke-Expression" nocase
    condition:
        $ps1 and any of ($ps2, $ps3, $ps4, $ps5, $ps6, $ps7)
}
"""

EDUCATIONAL_NOTICE = """
            !!! EDUCATIONAL NOTICE !!!
THIS SOFTWARE IS FOR EDUCATIONAL PURPOSES ONLY.
DO NOT USE THIS CODE TO CREATE OR DISTRIBUTE MALWARE.
PURPOSE: To teach cybersecurity professionals to identify and analyze advanced obfuscation techniques.
"""

BANNER = f"""
        ⣿⠲⠤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⣸⡏⠀⠀⠀⠉⠳⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⣿⠀⠀⠀⠀⠀⠀⠀⠉⠲⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⢰⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠲⣄⠀⠀⠀⡰⠋⢙⣿⣦⡀⠀⠀⠀⠀⠀
        ⠸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣙⣦⣮⣤⡀⣸⣿⣿⣿⣆⠀⠀⠀⠀
        ⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⠀⣿⢟⣫⠟⠋⠀⠀⠀⠀
        ⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣷⣷⣿⡁⠀⠀⠀⠀⠀⠀
                    ⢸⣿⢸⣿⣿⣧⣿⣿⣆⠙⢆⡀⠀⠀⠀⠀
                    ⢾⣿⣤⣿⣿⣿⡟⠹⣿⣿⣿⣿⣷⡀⠀⠀
                    ⢸⣿⣿⣿⣿⣿⣧⣴⣿⣿⣿⣿⠏⢧⠀⠀
                    ⣼⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠈⢳⡀
                    ⢠⡏⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⢳
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
        ███╗   ███╗ ██████╗ ██████╗ ██████╗ ██╗  ██╗
        ████╗ ████║██╔═══██╗██╔══██╗██╔══██╗██║  ██║
        ██╔████╔██║██║   ██║██████╔╝██████╔╝███████║
        ██║╚██╔╝██║██║   ██║██╔══██╗██╔═══╝ ██╔══██║
        ██║ ╚═╝ ██║╚██████╔╝██║  ██║██║     ██║  ██║
        ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝
                    RED TEAM TOOL
        ULTIMATE SECURITY RESEARCH TOOL v{VERSION}
        Developed by: {GITHUB_URL}
"""

class ConsoleUI:
    def __init__(self):
        self.rich_console = None
        self.setup_console()

    def setup_console(self):
        if RICH_AVAILABLE:
            self.rich_console = Console()
            logger.info("Rich console UI enabled")
        elif COLORAMA_AVAILABLE:
            logger.info("Colorama console UI enabled")
        else:
            logger.info("Basic interface enabled")

    def clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")

    def print_banner(self):
        if RICH_AVAILABLE:
            self.rich_console.print(BANNER, style="bold green")
        else:
            print(BANNER)

    def print_notice(self):
        if RICH_AVAILABLE:
            self.rich_console.print(EDUCATIONAL_NOTICE, style="bold red")
        elif COLORAMA_AVAILABLE:
            print(f"{Fore.RED}{Style.BRIGHT}{EDUCATIONAL_NOTICE}{Style.RESET_ALL}")
        else:
            print(EDUCATIONAL_NOTICE)

    def print_menu(self, title, options: Dict):
        if RICH_AVAILABLE:
            table = Table(show_header=False, box=None)
            table.add_column("Option", style="cyan", width=6)
            table.add_column("Description", style="white")
            self.rich_console.print(f"\n[bold magenta]{title}[/bold magenta]")
            for key, value in options.items():
                table.add_row(str(key), value)
            self.rich_console.print(table)
        elif COLORAMA_AVAILABLE:
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{title}{Style.RESET_ALL}")
            for key, value in options.items():
                print(f"{Fore.CYAN}{key}{Style.RESET_ALL}: {value}")
        else:
            print(f"\n--- {title} ---")
            for key, value in options.items():
                print(f"{key}: {value}")

    def get_input(self, prompt):
        if RICH_AVAILABLE:
            return self.rich_console.input(f"[cyan]{prompt}[/cyan] ")
        elif COLORAMA_AVAILABLE:
            return input(f"{Fore.CYAN}{prompt}{Style.RESET_ALL} ")
        else:
            return input(f"{prompt} ")

    def print_list(self, title, items, numbered=True):
        if RICH_AVAILABLE:
            self.rich_console.print(f"\n[bold blue]{title}[/bold blue]")
            table = Table(show_header=False, box=None)
            table.add_column("Index", style="green", width=5)
            table.add_column("Item", style="white")
            for idx, item in enumerate(items, 1):
                table.add_row(str(idx) if numbered else "", item)
            self.rich_console.print(table)
        elif COLORAMA_AVAILABLE:
            print(f"\n{Fore.BLUE}{Style.BRIGHT}{title}{Style.RESET_ALL}")
            for idx, item in enumerate(items, 1):
                print(f"{Fore.GREEN}{idx if numbered else ''}{Style.RESET_ALL} {item}")
        else:
            print(f"\n--- {title} ---")
            for idx, item in enumerate(items, 1):
                print(f"{idx if numbered else ''} {item}")

    def print_code(self, code, language="python"):
        if RICH_AVAILABLE:
            from rich.syntax import Syntax
            syntax = Syntax(code, language, theme="monokai", line_numbers=True)
            self.rich_console.print(syntax)
        else:
            print(code)

class MalwareAnalyzer:
    def __init__(self):
        if MODEL_AVAILABLE:
            logger.info("Loading text classification model (educational)...")
            try:
                self.model = pipeline("text-classification", model="bert-base-uncased")
            except Exception as e:
                logger.error(f"Error loading model: {e}")
                self.model = None
        else:
            self.model = None

    def calculate_entropy(self, data):
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return entropy

    def extract_strings(self, data, min_length=5):
        pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
        strings = re.findall(pattern, data)
        decoded_strings = []
        for s in strings:
            try:
                decoded_strings.append(s.decode("utf-8"))
            except UnicodeDecodeError:
                continue
        return " ".join(decoded_strings)

    def analyze_file(self, file_path):
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            return
        logger.info(f"Starting dynamic analysis for file: {file_path}")
        file_hash = hashlib.sha256(data).hexdigest()
        logger.info(f"SHA-256: {file_hash}")
        entropy = self.calculate_entropy(data)
        logger.info(f"Global Entropy: {entropy:.2f} (values > 7.0 may indicate obfuscation or encryption)")
        extracted_strings = self.extract_strings(data)
        if extracted_strings:
            logger.info("Extracted strings (truncated):")
            logger.info(f"{extracted_strings[:200]}{'...' if len(extracted_strings) > 200 else ''}")
            if self.model:
                truncated = extracted_strings[:512]
                try:
                    result = self.model(truncated)
                    logger.info(f"AI Classification Result: {result}")
                except Exception as e:
                    logger.error(f"Error during AI classification: {e}")
        else:
            logger.info("No significant strings found.")
        if data[:2] == b'MZ' and pefile:
            try:
                pe = pefile.PE(data=data)
                self.analyze_pe(pe)
            except Exception as e:
                logger.warning(f"Error analyzing PE: {e}")
        else:
            logger.info("File does not have 'MZ' signature or pefile is not installed.")
        self.analyze_packers(data)

    def analyze_pe(self, pe):
        logger.info("Analyzing PE structure of the file...")
        logger.info(f"Timestamp: {pe.FILE_HEADER.TimeDateStamp}")
        logger.info(f"Number of sections: {len(pe.sections)}")
        for section in pe.sections:
            section_name = section.Name.decode(errors="ignore").rstrip("\x00")
            section_data = section.get_data()
            section_entropy = self.calculate_entropy(section_data)
            logger.info(f"Section: {section_name} - Size: {section.SizeOfRawData} bytes - Entropy: {section_entropy:.2f}")
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="ignore")
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode(errors="ignore"))
                    else:
                        functions.append(f"ord_{imp.ordinal}")
                logger.info(f"Imported from {dll_name}: {functions}")
        else:
            logger.info("Import directory not found.")

    def analyze_packers(self, data):
        packer_signatures = {
            "UPX": b"UPX!",
            "ASPack": b".aspack",
            "Themida": b"Themida",
            "MPRESS": b"MPRESS"
        }
        logger.info("Analyzing known packers signatures...")
        for name, signature in packer_signatures.items():
            if signature in data:
                logger.info(f"Signature detected: {name}")
            else:
                logger.info(f"Signature not detected: {name}")

class PayloadSimulator:
    def __init__(self):
        self.insert_length = 10

    def generate_payload_obfuscation(self, base_payload: str) -> str:
        reversed_payload = base_payload[::-1]
        encoded_payload = base64.b64encode(reversed_payload.encode()).decode()
        random_inserts = ''.join(random.choices(string.ascii_letters + string.digits, k=self.insert_length))
        return f"{random_inserts}{encoded_payload}{random_inserts}"

    def deobfuscate_payload_obfuscation(self, obf_payload: str) -> str:
        if len(obf_payload) < 2 * self.insert_length:
            return "Invalid payload for deobfuscation."
        core = obf_payload[self.insert_length:-self.insert_length]
        try:
            decoded = base64.b64decode(core.encode()).decode()
        except Exception as e:
            return f"Decoding error: {e}"
        return decoded[::-1]

    def generate_payload_xor(self, base_payload: str) -> str:
        key = random.randint(1, 255)
        xor_result = ''.join(chr(ord(c) ^ key) for c in base_payload)
        encoded_result = base64.b64encode(xor_result.encode()).decode()
        return f"XOR-Key({key}):{encoded_result}"

    def deobfuscate_payload_xor(self, xor_payload: str) -> str:
        try:
            prefix, encoded = xor_payload.split(":", 1)
            key_str = prefix.strip()[8:-1]
            key = int(key_str)
            decoded = base64.b64decode(encoded.encode()).decode()
            return ''.join(chr(ord(c) ^ key) for c in decoded)
        except Exception as e:
            return f"Error in XOR deobfuscation: {e}"

    def generate_payload_substitution(self, base_payload: str) -> str:
        chars = set(base_payload)
        mapping = {c: random.choice(string.ascii_letters + string.digits) for c in chars}
        substituted = ''.join(mapping.get(c, c) for c in base_payload)
        mapping_str = ''.join(f"{k}:{v};" for k, v in mapping.items())
        encoded_mapping = base64.b64encode(mapping_str.encode()).decode()
        encoded_substituted = base64.b64encode(substituted.encode()).decode()
        noise = ''.join(random.choices(string.ascii_letters + string.digits, k=self.insert_length))
        return f"{noise}{encoded_mapping}{noise}{encoded_substituted}{noise}"

    def deobfuscate_payload_substitution(self, payload: str) -> str:
        try:
            noise = payload[:self.insert_length]
            parts = payload.split(noise)
            if len(parts) < 4:
                return "Invalid payload for substitution deobfuscation."
            encoded_mapping = parts[1]
            encoded_substituted = parts[2]
            mapping_str = base64.b64decode(encoded_mapping.encode()).decode()
            mapping = {}
            for pair in mapping_str.strip(';').split(';'):
                if pair:
                    k, v = pair.split(":")
                    mapping[v] = k
            substituted = base64.b64decode(encoded_substituted.encode()).decode()
            original = ''.join(mapping.get(c, c) for c in substituted)
            return original
        except Exception as e:
            return f"Error in substitution deobfuscation: {e}"

    def generate_payload_caesar(self, base_payload: str, shift: int = None) -> str:
        if shift is None:
            shift = random.randint(1, 25)
        def shift_char(c):
            if c.isalpha():
                start = ord('A') if c.isupper() else ord('a')
                return chr((ord(c) - start + shift) % 26 + start)
            return c
        ciphered = ''.join(shift_char(c) for c in base_payload)
        return f"CAESAR({shift}):{ciphered}"

    def deobfuscate_payload_caesar(self, caesar_payload: str) -> str:
        try:
            prefix, ciphered = caesar_payload.split(":", 1)
            shift = int(prefix.strip()[8:-1])
            def unshift_char(c):
                if c.isalpha():
                    start = ord('A') if c.isupper() else ord('a')
                    return chr((ord(c) - start - shift) % 26 + start)
                return c
            return ''.join(unshift_char(c) for c in ciphered)
        except Exception as e:
            return f"Error in Caesar deobfuscation: {e}"

    def generate_payload_polymorphic(self, base_payload: str) -> str:
        step1 = self.generate_payload_obfuscation(base_payload)
        step2 = self.generate_payload_xor(step1)
        return step2

    def deobfuscate_payload_polymorphic(self, poly_payload: str) -> str:
        intermediate = self.deobfuscate_payload_xor(poly_payload)
        original = self.deobfuscate_payload_obfuscation(intermediate)
        return original

    def generate_payload_extreme(self, base_payload: str) -> str:
        step1 = self.generate_payload_substitution(base_payload)
        step2 = self.generate_payload_xor(step1)
        step3 = self.generate_payload_obfuscation(step2)
        return step3

    def deobfuscate_payload_extreme(self, extreme_payload: str) -> str:
        step1 = self.deobfuscate_payload_obfuscation(extreme_payload)
        step2 = self.deobfuscate_payload_xor(step1)
        original = self.deobfuscate_payload_substitution(step2)
        return original

    def generate_payload_advanced(self, base_payload: str) -> str:
        methods = [
            self.generate_payload_obfuscation,
            self.generate_payload_xor,
            self.generate_payload_substitution,
            self.generate_payload_caesar
        ]
        first = random.choice(methods)
        intermediate = first(base_payload)
        second = random.choice(methods)
        if second == self.generate_payload_caesar:
            return second(intermediate, shift=random.randint(1, 25))
        return second(intermediate)

    def deobfuscate_payload_advanced(self, advanced_payload: str) -> str:
        return "Advanced deobfuscation not implemented due to the random nature of the technique."

    def generate_payload_encrypted(self, base_payload: str) -> str:
        if not Fernet:
            return "Cryptography library not installed."
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted = cipher.encrypt(base_payload.encode()).decode()
        noise = ''.join(random.choices(string.ascii_letters + string.digits, k=self.insert_length))
        return f"{noise}{encrypted}{noise}", key

    def deobfuscate_payload_encrypted(self, encrypted_payload: str, key: bytes) -> str:
        if not Fernet:
            return "Cryptography library not installed."
        if len(encrypted_payload) < 2 * self.insert_length:
            return "Invalid payload."
        core = encrypted_payload[self.insert_length:-self.insert_length]
        try:
            cipher = Fernet(key)
            decrypted = cipher.decrypt(core.encode()).decode()
            return decrypted
        except Exception as e:
            return f"Decryption error: {e}"

class NetworkAnalyzer:
    def __init__(self):
        self.ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.url_regex = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
        self.domain_regex = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

    def extract_network_indicators(self, data):
        if isinstance(data, bytes):
            try:
                text_data = data.decode('utf-8', errors='ignore')
            except Exception:
                text_data = str(data)
        else:
            text_data = str(data)
        ips = self.ip_regex.findall(text_data)
        urls = self.url_regex.findall(text_data)
        domains = self.domain_regex.findall(text_data)
        valid_ips = []
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local:
                    valid_ips.append(ip)
            except ValueError:
                continue
        filtered_domains = []
        common_false_positives = ['com.', 'org.', 'net.', 'co.uk', 'io.', 'example.com']
        for domain in domains:
            if not any(domain == fp or domain.endswith('.' + fp) for fp in common_false_positives):
                filtered_domains.append(domain)
        return {
            'ips': list(set(valid_ips)),
            'urls': list(set(urls)),
            'domains': list(set(filtered_domains))
        }

    def analyze(self, data):
        indicators = self.extract_network_indicators(data)
        if not any(indicators.values()):
            logger.info("No network indicators found")
            return None
        logger.info(f"Found {len(indicators['ips'])} IPs, {len(indicators['urls'])} URLs and {len(indicators['domains'])} domains")
        return indicators

    def check_reputation(self, indicator):
        if not REQUESTS_AVAILABLE:
            return "Reputation check requires the requests library"
        try:
            return "Simulated reputation check (would connect to threat intelligence APIs)"
        except Exception as e:
            logger.error(f"Error checking reputation: {e}")
            return None

class StaticAnalyzer:
    def __init__(self):
        self.network_analyzer = NetworkAnalyzer()
        self.yara_rules = None
        if YARA_AVAILABLE:
            try:
                self.yara_rules = yara.compile(source=DEFAULT_YARA_RULES)
                logger.info("YARA rules compiled successfully")
            except Exception as e:
                logger.error(f"Error compiling YARA rules: {e}")

    def calculate_entropy(self, data, block_size=256):
        if not data:
            return 0.0
        if block_size is None:
            entropy = 0
            for x in range(256):
                p_x = float(data.count(bytes([x]))) / len(data)
                if p_x > 0:
                    entropy += -p_x * math.log(p_x, 2)
            return entropy
        else:
            entropies = []
            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                if len(block) < 10:
                    continue
                block_entropy = 0
                for x in range(256):
                    p_x = float(block.count(bytes([x]))) / len(block)
                    if p_x > 0:
                        block_entropy += -p_x * math.log(p_x, 2)
                entropies.append((i, block_entropy))
            return entropies

    def extract_strings(self, data, min_length=4, wide=True):
        ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
        ascii_strings = re.findall(ascii_pattern, data)
        unicode_strings = []
        if wide:
            wide_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
            wide_matches = re.findall(wide_pattern, data)
            for match in wide_matches:
                try:
                    decoded = match.decode('utf-16le', errors='ignore')
                    unicode_strings.append(decoded)
                except UnicodeDecodeError:
                    continue
        decoded_ascii = []
        for s in ascii_strings:
            try:
                decoded_ascii.append(s.decode('utf-8', errors='ignore'))
            except UnicodeDecodeError:
                continue
        return {
            'ascii': decoded_ascii,
            'unicode': unicode_strings
        }

    def analyze_pe(self, pe_file):
        if not PEFILE_AVAILABLE:
            return "PE analysis requires the pefile library"
        try:
            pe = pefile.PE(data=pe_file) if isinstance(pe_file, bytes) else pefile.PE(pe_file)
            result = {
                'header': {
                    'machine': hex(pe.FILE_HEADER.Machine),
                    'timestamp': pe.FILE_HEADER.TimeDateStamp,
                    'compiled_time': datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S'),
                    'characteristics': hex(pe.FILE_HEADER.Characteristics),
                    'subsystem': pe.OPTIONAL_HEADER.Subsystem if hasattr(pe, 'OPTIONAL_HEADER') else 'N/A',
                    'dll_characteristics': hex(pe.OPTIONAL_HEADER.DllCharacteristics) if hasattr(pe, 'OPTIONAL_HEADER') else 'N/A'
                },
                'sections': [],
                'imports': {},
                'exports': [],
                'resources': [],
                'debug_info': []
            }
            for section in pe.sections:
                section_name = section.Name.decode(errors="ignore").rstrip("\x00")
                section_data = section.get_data()
                section_entropy = self.calculate_entropy(section_data, block_size=None)
                section_info = {
                    'name': section_name,
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': section_entropy,
                    'characteristics': hex(section.Characteristics)
                }
                result['sections'].append(section_info)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode(errors="ignore")
                    imports = []
                    for imp in entry.imports:
                        if imp.name:
                            imports.append(imp.name.decode(errors="ignore"))
                        else:
                            imports.append(f"ord_{imp.ordinal}")
                    result['imports'][dll_name] = imports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    export_name = exp.name.decode(errors="ignore") if exp.name else f"ord_{exp.ordinal}"
                    result['exports'].append({
                        'name': export_name,
                        'address': hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),
                        'ordinal': exp.ordinal
                    })
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    try:
                                        data = pe.get_data(
                                            resource_lang.data.struct.OffsetToData,
                                            resource_lang.data.struct.Size
                                        )
                                        resource_info = {
                                            'type': resource_type.id,
                                            'id': resource_id.id,
                                            'lang': resource_lang.id,
                                            'size': resource_lang.data.struct.Size,
                                            'entropy': self.calculate_entropy(data, block_size=None)
                                        }
                                        result['resources'].append(resource_info)
                                    except Exception as e:
                                        logger.error(f"Error extracting resource: {e}")
            if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                for dbg in pe.DIRECTORY_ENTRY_DEBUG:
                    debug_info = {
                        'type': dbg.struct.Type,
                        'timestamp': dbg.struct.TimeDateStamp,
                        'debug_time': datetime.fromtimestamp(dbg.struct.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S') if dbg.struct.TimeDateStamp else 'N/A'
                    }
                    result['debug_info'].append(debug_info)
            return result
        except Exception as e:
            logger.error(f"Error in PE analysis: {e}")
            return f"Error analyzing PE: {e}"

    def detect_packers(self, data):
        packer_signatures = {
            "UPX": [b"UPX!", b"UPX0", b"UPX1", b"UPX2", b"UPX3"],
            "ASPack": [b".aspack", b"ASPack"],
            "Themida": [b"Themida", b"WinLicense"],
            "VMProtect": [b"VMProtect", b"vmp0"],
            "Enigma": [b"Enigma"],
            "Obsidium": [b"Obsidium"],
            "MPress": [b"MPRESS", b"MPRESS1", b"MPRESS2"],
            "PECompact": [b"PEC2", b"PECompact2"],
            "ExeStealth": [b"ExeStealth"],
            "NSIS": [b"Nullsoft", b"NSIS"],
            "Armadillo": [b"Armadillo", b".armadillo"]
        }
        detected = []
        for name, signatures in packer_signatures.items():
            for signature in signatures:
                if signature in data:
                    detected.append(name)
                    break
        return list(set(detected))

    def scan_with_yara(self, data):
        if not YARA_AVAILABLE or not self.yara_rules:
            return []
        try:
            matches = self.yara_rules.match(data=data)
            return [match.rule for match in matches]
        except Exception as e:
            logger.error(f"Error during YARA scan: {e}")
            return []

    def extract_interesting_strings(self, strings_dict):
        keywords = ['http', 'https', 'www', '.com', '.net', '.org', 'cmd', 'powershell', 'eval', 'base64']
        interesting = []
        for s in strings_dict['ascii'] + strings_dict['unicode']:
            if any(kw in s.lower() for kw in keywords) and len(s) >= 8:
                interesting.append(s)
        return interesting

    def is_binary_file(self, data):
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
        if not data:
            return False
        nontext = data.translate(None, text_chars)
        return float(len(nontext)) / len(data) > 0.30

    def identify_file_type(self, data):
        if data.startswith(b'MZ'):
            return "PE"
        elif data.startswith(b'\x7fELF'):
            return "ELF"
        elif data.startswith(b'\xCA\xFE\xBA\xBE') or data.startswith(b'\xFE\xED\xFA\xCE'):
            return "Mach-O"
        else:
            return "Unknown"

    def analyze_file(self, file_path, detailed=False):
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return {"error": "File not found"}
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            return {"error": f"Error reading file: {e}"}
        logger.info(f"Performing static analysis on file: {file_path} ({len(data)} bytes)")
        file_info = {
            'path': os.path.abspath(file_path),
            'size': len(data),
            'sha256': hashlib.sha256(data).hexdigest(),
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'file_type': self.identify_file_type(data),
            'entropy': self.calculate_entropy(data, block_size=None),
            'is_binary': self.is_binary_file(data)
        }
        if detailed:
            logger.info("Performing detailed block entropy analysis...")
            file_info['block_entropy'] = self.calculate_entropy(data, block_size=256)
        strings = self.extract_strings(data)
        file_info['strings'] = {
            'ascii_count': len(strings['ascii']),
            'unicode_count': len(strings['unicode']),
            'interesting': self.extract_interesting_strings(strings)
        }
        network_indicators = self.network_analyzer.analyze(data)
        if network_indicators:
            file_info['network_indicators'] = network_indicators
        yara_matches = self.scan_with_yara(data)
        if yara_matches:
            file_info['yara_matches'] = yara_matches
        if file_info['file_type'] == "PE" and PEFILE_AVAILABLE:
            pe_analysis = self.analyze_pe(data)
            file_info['pe_analysis'] = pe_analysis
        packers = self.detect_packers(data)
        if packers:
            file_info['packers'] = packers
        return file_info

def simulate_environment_detection() -> bool:
    suspicious = False
    if os.name == "nt":
        if os.path.exists("C:\\windows\\system32\\drivers\\vmmouse.sys"):
            suspicious = True
    else:
        dmi_path = "/sys/class/dmi/id/product_name"
        if os.path.exists(dmi_path):
            try:
                with open(dmi_path, "r") as f:
                    product_name = f.read().strip()
                for keyword in ["VirtualBox", "VMware", "KVM", "QEMU", "Hyper-V", "Xen"]:
                    if keyword.lower() in product_name.lower():
                        suspicious = True
                        break
            except Exception as e:
                logger.error(f"Error reading {dmi_path}: {e}")
    return suspicious

def enhanced_environment_detection() -> bool:
    suspicious = simulate_environment_detection()
    if os.name != "nt":
        try:
            result = subprocess.run(["systemd-detect-virt", "--vm"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0 and result.stdout.strip() != "":
                suspicious = True
        except Exception:
            pass
        if os.path.exists("/proc/scsi/scsi"):
            try:
                with open("/proc/scsi/scsi", "r") as f:
                    contents = f.read().lower()
                    if "vmware" in contents or "virtual" in contents or "vbox" in contents:
                        suspicious = True
            except Exception:
                pass
    return suspicious

def main_menu():
    ui = ConsoleUI()
    analyzer_dynamic = MalwareAnalyzer()
    analyzer_static = StaticAnalyzer()
    simulator = PayloadSimulator()
    net_analyzer = NetworkAnalyzer()
    ui.clear_screen()
    ui.print_banner()
    ui.print_notice()
    while True:
        print("\n" + "="*50 + "\n")
        options = {
            "1": "List files in current directory",
            "2": "Dynamic Analysis (MalwareAnalyzer)",
            "3": "Static Analysis (StaticAnalyzer)",
            "4": "Payload Generation",
            "5": "Payload Deobfuscation",
            "6": "Network Indicators Analysis in a File",
            "7": "Virtual Environment Detection (comprehensive)",
            "0": "Exit"
        }
        ui.print_menu("MAIN MENU", options)
        choice = ui.get_input("Choose an option").strip()
        if choice == "1":
            files = [f for f in os.listdir(os.getcwd()) if os.path.isfile(os.path.join(os.getcwd(), f))]
            if not files:
                ui.get_input("No files found in current directory. (Enter to continue)")
            else:
                ui.print_list("Files in current directory", files)
                ui.get_input("(Enter to return to menu)")
        elif choice == "2":
            dir_choice = ui.get_input("Use current directory? (Y/N)").strip().lower()
            if dir_choice == "n":
                dir_path = ui.get_input("Enter full directory path")
            else:
                dir_path = os.getcwd()
            if not os.path.isdir(dir_path):
                ui.get_input("Invalid directory. (Enter to return)")
                continue
            files = [f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))]
            if not files:
                ui.get_input("No files found in this directory. (Enter to return)")
                continue
            ui.print_list("Select a file for Dynamic Analysis", files)
            try:
                idx = int(ui.get_input("Enter file number"))
                if 1 <= idx <= len(files):
                    file_path = os.path.join(dir_path, files[idx-1])
                    analyzer_dynamic.analyze_file(file_path)
                else:
                    ui.get_input("Invalid number. (Enter to return)")
            except ValueError:
                ui.get_input("Invalid input. (Enter to return)")
        elif choice == "3":
            dir_choice = ui.get_input("Use current directory? (Y/N)").strip().lower()
            if dir_choice == "n":
                dir_path = ui.get_input("Enter full directory path")
            else:
                dir_path = os.getcwd()
            if not os.path.isdir(dir_path):
                ui.get_input("Invalid directory. (Enter to return)")
                continue
            files = [f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))]
            if not files:
                ui.get_input("No files found in this directory. (Enter to return)")
                continue
            ui.print_list("Select a file for Static Analysis", files)
            try:
                idx = int(ui.get_input("Enter file number"))
                if 1 <= idx <= len(files):
                    file_path = os.path.join(dir_path, files[idx-1])
                    result = analyzer_static.analyze_file(file_path, detailed=True)
                    if RICH_AVAILABLE:
                        from rich.panel import Panel
                        from rich.json import JSON
                        ui.rich_console.print(Panel.fit(JSON.from_data(result), title="Static Analysis Result", border_style="green"))
                    else:
                        print(json.dumps(result, indent=4))
                else:
                    ui.get_input("Invalid number. (Enter to return)")
            except ValueError:
                ui.get_input("Invalid input. (Enter to return)")
        elif choice == "4":
            base_payload = ui.get_input("Enter base payload (e.g., benign text)")
            gen_options = {
                "1": "Simple Obfuscation",
                "2": "XOR",
                "3": "Substitution",
                "4": "Caesar Cipher",
                "5": "Polymorphic (XOR + Obfuscation)",
                "6": "Extreme Combination (Substitution + XOR + Obfuscation)",
                "7": "Advanced (random selection)",
                "8": "Symmetric Encryption (if available)"
            }
            ui.print_menu("PAYLOAD GENERATION MENU", gen_options)
            option = ui.get_input("Choose method").strip()
            if option == "1":
                result = simulator.generate_payload_obfuscation(base_payload)
                print(f"\nPayload (Simple Obfuscation):\n{result}")
            elif option == "2":
                result = simulator.generate_payload_xor(base_payload)
                print(f"\nPayload (XOR):\n{result}")
            elif option == "3":
                result = simulator.generate_payload_substitution(base_payload)
                print(f"\nPayload (Substitution):\n{result}")
            elif option == "4":
                result = simulator.generate_payload_caesar(base_payload)
                print(f"\nPayload (Caesar Cipher):\n{result}")
            elif option == "5":
                result = simulator.generate_payload_polymorphic(base_payload)
                print(f"\nPayload (Polymorphic):\n{result}")
            elif option == "6":
                result = simulator.generate_payload_extreme(base_payload)
                print(f"\nPayload (Extreme Combination):\n{result}")
            elif option == "7":
                result = simulator.generate_payload_advanced(base_payload)
                print(f"\nPayload (Advanced):\n{result}")
            elif option == "8":
                result_key = simulator.generate_payload_encrypted(base_payload)
                if isinstance(result_key, tuple):
                    result, key = result_key
                    print(f"\nEncrypted Payload:\n{result}")
                    print(f"Encryption key: {key.decode()}")
                else:
                    print(f"\n{result_key}")
            else:
                print("Invalid option.")
        elif choice == "5":
            deobf_options = {
                "1": "Simple Obfuscation",
                "2": "XOR",
                "3": "Substitution",
                "4": "Caesar Cipher",
                "5": "Polymorphic (XOR + Obfuscation)",
                "6": "Extreme Combination (Substitution + XOR + Obfuscation)",
                "7": "Advanced (random selection)",
                "8": "Symmetric Encryption (if available)"
            }
            ui.print_menu("PAYLOAD DEOBFUSCATION MENU", deobf_options)
            option = ui.get_input("Choose method").strip()
            payload = ui.get_input("Paste payload")
            if option == "1":
                original = simulator.deobfuscate_payload_obfuscation(payload)
                print(f"\nOriginal Payload:\n{original}")
            elif option == "2":
                original = simulator.deobfuscate_payload_xor(payload)
                print(f"\nOriginal Payload:\n{original}")
            elif option == "3":
                original = simulator.deobfuscate_payload_substitution(payload)
                print(f"\nOriginal Payload:\n{original}")
            elif option == "4":
                original = simulator.deobfuscate_payload_caesar(payload)
                print(f"\nOriginal Payload:\n{original}")
            elif option == "5":
                original = simulator.deobfuscate_payload_polymorphic(payload)
                print(f"\nOriginal Payload:\n{original}")
            elif option == "6":
                original = simulator.deobfuscate_payload_extreme(payload)
                print(f"\nOriginal Payload:\n{original}")
            elif option == "7":
                original = simulator.deobfuscate_payload_advanced(payload)
                print(f"\nAdvanced Deobfuscation Result:\n{original}")
            elif option == "8":
                if not Fernet:
                    print("Cryptography library not installed.")
                else:
                    key_input = ui.get_input("Paste encryption key")
                    try:
                        key = key_input.encode()
                        original = simulator.deobfuscate_payload_encrypted(payload, key)
                        print(f"\nOriginal Payload:\n{original}")
                    except Exception as e:
                        print(f"Error: {e}")
            else:
                print("Invalid option.")
        elif choice == "6":
            dir_choice = ui.get_input("Use current directory? (Y/N)").strip().lower()
            if dir_choice == "n":
                dir_path = ui.get_input("Enter full directory path")
            else:
                dir_path = os.getcwd()
            if not os.path.isdir(dir_path):
                ui.get_input("Invalid directory. (Enter to return)")
                continue
            files = [f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))]
            if not files:
                ui.get_input("No files found in this directory. (Enter to return)")
                continue
            ui.print_list("Select a file for Network Indicators Analysis", files)
            try:
                idx = int(ui.get_input("Enter file number"))
                if 1 <= idx <= len(files):
                    file_path = os.path.join(dir_path, files[idx-1])
                    try:
                        with open(file_path, "rb") as f:
                            data = f.read()
                        indicators = net_analyzer.extract_network_indicators(data)
                        if indicators:
                            print("Network Indicators Found:")
                            print(json.dumps(indicators, indent=4))
                        else:
                            print("No network indicators found.")
                    except Exception as e:
                        print(f"Error reading file: {e}")
                else:
                    ui.get_input("Invalid number. (Enter to return)")
            except ValueError:
                ui.get_input("Invalid input. (Enter to return)")
        elif choice == "7":
            env = enhanced_environment_detection()
            status = "Virtual environment detected!" if env else "No virtualization indicators detected."
            print(f"\nEnvironment Detection Result: {status}")
        elif choice == "0":
            print("Exiting...")
            sys.exit(0)
        else:
            ui.get_input("Invalid option. (Enter to try again)")

def main():
    parser = argparse.ArgumentParser(description="Ultimate Security Research Tool - Dynamic & Static Analysis, Payload Generation/Deobfuscation, Network Indicators and more.")
    parser.add_argument("--menu", action="store_true", help="Run interactive menu")
    parser.add_argument("--file", help="Path to file for analysis (static analysis will be performed)")
    parser.add_argument("-d", "--detailed", action="store_true", help="Perform detailed static analysis")
    args = parser.parse_args()
    if args.menu or not args.file:
        main_menu()
    else:
        file_path = args.file
        print(BANNER)
        print(EDUCATIONAL_NOTICE)
        print(f"\nPerforming Dynamic Analysis on {file_path}...\n")
        dynamic_analyzer = MalwareAnalyzer()
        dynamic_analyzer.analyze_file(file_path)
        print(f"\nPerforming Static Analysis on {file_path}...\n")
        static_analyzer = StaticAnalyzer()
        result = static_analyzer.analyze_file(file_path, detailed=args.detailed)
        print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()
