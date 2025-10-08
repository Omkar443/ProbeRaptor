````markdown
# ProbeRaptor

**ProbeRaptor** — modular, professional reconnaissance for bug bounty hunters and security researchers.  
Built in Python for fast subdomain discovery, wordlist enumeration, and multi-threaded port scanning.

> ⚠️ **Important**: Only run ProbeRaptor against targets you own or have explicit written permission to test. Unauthorized scanning can be illegal.

---

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE) [![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](#requirements) [![Release](https://img.shields.io/github/v/release/Omkar443/ProbeRaptor)](https://github.com/Omkar443/ProbeRaptor/releases)

## Quick Start

```bash
git clone https://github.com/Omkar443/ProbeRaptor.git
cd ProbeRaptor
pip install -r requirements.txt
python3 proberaptor.py -d example.com
````

Show CLI help:

```bash
python3 proberaptor.py --help
```

---

## Features

* **Subdomain discovery**: crt.sh, HackerTarget APIs + custom wordlists
* **Multi-threaded port scanning** with banner grabbing & service identification
* **Flexible output**: console, JSON, HTML report formats
* **Reporting**: scoring/prioritization and actionable next steps
* **Performance**: configurable threads, ETA and progress reporting

---

## Installation & Requirements

* Python **3.8+** (recommended 3.10+)
* Tested on Linux / macOS

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage Examples

Basic scan:

```bash
python3 proberaptor.py -d example.com
```

Subdomain-only:

```bash
python3 proberaptor.py -d example.com -s subdomains -o json --output-dir outputs/
```

Full scan (APIs + wordlist + ports):

```bash
python3 proberaptor.py -d example.com -s full --wordlist wordlists/common_subdomains.txt -o html
```

Output formats:

* `console` (default)
* `json`
* `html`

---

## Project Structure

```
ProbeRaptor/
├── proberaptor.py
├── config/
│   └── settings.py
├── modules/
│   ├── api_enumerator.py
│   ├── subdomain_enum.py
│   └── port_scanner.py
├── utils/
│   └── helpers.py
├── wordlists/
├── outputs/
├── requirements.txt
└── README.md
```

---

## Example JSON Output

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

## Configuration

Edit `config/settings.py` to tune defaults:

```python
def get_version(): return "1.0.0"
def get_user_agent(): return "ProbeRaptor/1.0"
def get_default_timeout(): return 10
def get_default_threads(): return 50
```

---

## Contributing

Contributions are welcome! Please:

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Commit and open a PR

See `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` for details.

---

## Tests

(If you add tests) Run:

```bash
python3 -m pytest tests/
```

---

## License

ProbeRaptor is released under the **MIT License** — see `LICENSE`.

---

## Acknowledgements

Built with ❤️ by **Omkar Sahni**. Thanks to the security community for shared knowledge and inspiration.

---

⭐ If ProbeRaptor helps you, please give the repo a star!

---

"The eagle-eyed approach to reconnaissance"

```
```
