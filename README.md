# ProbeRaptor

**ProbeRaptor** 🦅 — a modular, professional reconnaissance tool for bug bounty hunters and security researchers.  
Built in Python, it offers fast subdomain discovery, wordlist enumeration, and multi-threaded port scanning.

> ⚠️ **Important:** Only run ProbeRaptor on targets you own or have explicit written permission to test. Unauthorized scanning may be illegal.

---

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE) [![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](#requirements) [![Release](https://img.shields.io/github/v/release/Omkar443/ProbeRaptor)](https://github.com/Omkar443/ProbeRaptor/releases)

---

## 🚀 Quick Start

Clone the repo and install dependencies:

```bash
git clone https://github.com/Omkar443/ProbeRaptor.git
cd ProbeRaptor
pip install -r requirements.txt
````

Run a basic scan:

```bash
python3 proberaptor.py -d example.com
```

Check available options:

```bash
python3 proberaptor.py --help
```

---

## 🌟 Features

### Subdomain Discovery

* Certificate Transparency Logs via crt.sh
* API integrations (HackerTarget)
* Wordlist enumeration with duplicates removed

### Service Detection

* Multi-threaded TCP port scanning
* Service identification and banner grabbing
* Pre-defined scan profiles (web, common, full)

### Reporting & Analysis

* JSON, HTML, and console outputs
* Priority scoring (0–100)
* Scan duration, success rates, and coverage statistics

### Performance & Reliability

* Multi-threaded with configurable worker count
* Duplicate prevention across all sources
* ETA and progress tracking for large scans

---

## ⚙️ Installation & Requirements

* **Python 3.8+** (recommended 3.10+)
* Linux or macOS (tested)

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🎯 Usage Examples

### Basic Scan

```bash
python3 proberaptor.py -d example.com
```

### Subdomain-Only Scan

```bash
python3 proberaptor.py -d example.com -s subdomains -o json
```

### Full Scan (APIs + Wordlist + Ports)

```bash
python3 proberaptor.py -d example.com -s full --wordlist wordlists/common_subdomains.txt -o html
```

### Output Formats

* `console` (default)
* `json` (for automation)
* `html` (report generation)

---

## 📁 Project Structure

```
ProbeRaptor/
├── proberaptor.py              # Main entry point
├── config/
│   └── settings.py             # Configuration settings
├── modules/
│   ├── api_enumerator.py       # API-based subdomain discovery
│   ├── subdomain_enum.py       # Wordlist & verified subdomain enumeration
│   └── port_scanner.py         # Multi-threaded port scanning
├── utils/
│   └── helpers.py              # Utility functions
├── wordlists/
│   └── common_subdomains.txt   # Default wordlist
├── outputs/                    # Scan results (auto-created)
├── requirements.txt
└── README.md
```

---

## 💻 Configuration

Edit `config/settings.py`:

```python
def get_version(): return "1.0.0"
def get_user_agent(): return "ProbeRaptor/1.0"
def get_default_timeout(): return 10
def get_default_threads(): return 50
```

---

## 🧪 Example JSON Output

```json
{
  "tool": "ProbeRaptor",
  "version": "1.0.0",
  "target": "example.com",
  "results": [
    {
      "subdomain": "admin.example.com",
      "ip_address": "192.0.2.1",
      "status_code": 200,
      "open_ports": [{"port":80,"service":"HTTP"}],
      "score": 92
    }
  ]
}
```

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Commit your changes and open a Pull Request

See `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` for details.

---

## ⚖️ License

ProbeRaptor is licensed under the **MIT License** — see `LICENSE`.

---

## 🙏 Acknowledgements

Built with ❤️ by **Omkar Sahni**. Thanks to the security community for inspiration and shared knowledge.

---

⭐ If ProbeRaptor helps you, please give the repo a star!

*"The eagle-eyed approach to reconnaissance"*
