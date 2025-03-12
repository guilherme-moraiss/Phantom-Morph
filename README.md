# Phantom Morph

Phantom Morph is a powerful cybersecurity tool designed for ethical security research. It provides **dynamic and static file analysis**, **payload generation and deobfuscation**, **network indicator extraction**, and **virtual environment detection**. This tool is meant for **educational purposes** and helps security professionals learn advanced obfuscation and analysis techniques.

---

## Features  
- **Dynamic File Analysis**: Entropy analysis, string extraction, and AI-based classification  
- **Static Analysis**: PE structure inspection, entropy calculation, YARA scanning  
- **Payload Obfuscation**: XOR encoding, substitution ciphers, polymorphic encryption  
- **Network IOC Extraction**: IP/domain/URL detection in files  
- **Environment Detection**: Sandbox/VM/analysis environment checks  
- **YARA Integration**: Custom/predefined rule scanning  
- **Real-Time Logging**: Enhanced terminal output with Rich Console  

---

## Installation  

### Prerequisites  
- Python 3.6+  
- pip package manager  

### Setup  
```bash  
# Clone the repository  
git clone https://github.com/guilherme-moraiss/phantom-morph.git  
cd phantom-morph  

# Install dependencies  
pip install -r requirements.txt
````

---

## Usage

### Interactive Mode
```bash
  python3 phantom-morph.py --menu
```

---

## Command-Line Analysis
```bash
# Analyze a file  
python3 phantom-morph.py --file /path/to/file --detailed  

# Obfuscate payload  
python3 phantom-morph.py --payload "Sensitive Data" --method xor  

# Deobfuscate data  
python3 phantom-morph.py --deobfuscate "XOR-Key(42):b64_encoded_data"
```

---

### Customization

## Add YARA Rules
- **Edit yara_rules.txt
- **Add your rule:
  ```yara
  rule custom_malware {  
    strings:  
        $a = "malicious_string"  
    condition:  
        $a  }
  ```
## Modify Encryption Methods

Edit the PayloadSimulator class in phantom_morph.py to add/modify encryption techniques.

---

## Ethical Considerations
This tool is strictly for educational/research purposes . Do NOT use for:
- **Unauthorized system access
- **Malicious activities
- **Exploitation of systems
Comply with all applicable laws and ethical guidelines. Creators are not liable for misuse.

---

## Roadmap
- **VirusTotal API integration
- **Enhanced ML-based classification
- **Multi-language support
- **GUI interface

---

## License

This project is MIT licensed. See [LICENSE](LICENSE) for details.
