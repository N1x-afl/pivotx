
<div align="center">

```
  ██████╗ ██╗██╗   ██╗ ██████╗ ████████╗██╗  ██╗
  ██╔══██╗██║██║   ██║██╔═══██╗╚══██╔══╝╚██╗██╔╝
  ██████╔╝██║██║   ██║██║   ██║   ██║    ╚███╔╝ 
  ██╔═══╝ ██║╚██╗ ██╔╝██║   ██║   ██║    ██╔██╗ 
  ██║     ██║ ╚████╔╝ ╚██████╔╝   ██║   ██╔╝ ██╗
  ╚═╝     ╚═╝  ╚═══╝   ╚═════╝    ╚═╝   ╚═╝  ╚═╝
```

**Network Pivot Discovery Framework**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20Zorin-E95420?style=flat-square&logo=linux&logoColor=white)](https://kali.org)
[![License](https://img.shields.io/badge/License-MIT-00ff9d?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0-00d4ff?style=flat-square)]()
[![Maintained](https://img.shields.io/badge/Maintained-Yes-green?style=flat-square)]()

*Discover hosts, map pivot routes, analyze risks and generate interactive HTML reports — all in one tool.*

</div>

---

## 📸 Screenshots

> *(Add screenshots of your HTML report here — drag images into this section on GitHub)*

| Network Map | Port Analysis |
|---|---|
| ![Network Map](screenshots/netmap.png) | ![Port Chart](screenshots/ports.png) |

| Terminal Output | Full Report |
|---|---|
| ![Terminal](screenshots/terminal.png) | ![Report](screenshots/report.png) |

---

## ✨ Features

- 🔍 **Host Discovery** — ARP sweep (root) or Ping sweep (no root), auto-detected
- 🗺️ **Interactive Network Map** — drag-and-drop nodes, color-coded by risk level
- 📊 **Port Frequency Chart** — top 10 most common ports visualized
- ⚡ **Pivot Route Analysis** — auto-detects SSH tunnels, SOCKS5, SMB, WinRM, RDP paths
- 🎯 **Risk Scoring** — ranks every host by pivot potential (CRITICAL / HIGH / MEDIUM / LOW)
- 🖥️ **Banner Grabbing** — captures service banners for fingerprinting
- 📄 **Full HTML Report** — dark cyberpunk UI, expandable rows, suggested commands per host
- 📁 **Flexible Output** — save reports to Downloads, Documents, Desktop or any custom path
- 🐍 **Pure Python** — minimal dependencies, no external tools required

---

## 🚀 Quick Start

### Requirements

```bash
# Python 3.10+
python3 --version

# Install dependencies
pip3 install scapy netifaces
```

### Run

```bash
# Basic scan (auto-detects ARP or Ping sweep)
sudo python3 pivotx.py -n 192.168.1.0/24

# Save report to Documents folder
sudo python3 pivotx.py -n 192.168.1.0/24 --dir documentos

# Save report to Downloads with custom name
sudo python3 pivotx.py -n 192.168.1.0/24 --dir descargas -o my_report.html

# Aggressive scan (top 100 ports, 200 threads)
sudo python3 pivotx.py -n 192.168.1.0/24 -p top100 -t 200

# Host discovery only (no port scan)
sudo python3 pivotx.py -n 192.168.1.0/24 --ping-only
```

---

## ⚙️ Options

| Flag | Description | Default |
|------|-------------|---------|
| `-n`, `--network` | Target network in CIDR notation | *required* |
| `-p`, `--ports` | Port preset: `pivot`, `top50`, `top100`, `all` | `pivot` |
| `-o`, `--output` | Output HTML filename | `pivotx_report.html` |
| `-d`, `--dir` | Output folder alias or absolute path | current dir |
| `-t`, `--threads` | Threads for port scanning | `100` |
| `--no-banner` | Skip banner grabbing | off |
| `--ping-only` | Host discovery only, no port scan | off |
| `--top N` | Show only top N hosts by pivot score | all |

### `--dir` folder aliases

| Alias | Resolves to |
|-------|-------------|
| `descargas` / `downloads` | `~/Descargas` or `~/Downloads` |
| `documentos` / `documents` | `~/Documentos` or `~/Documents` |
| `escritorio` / `desktop` | `~/Escritorio` or `~/Desktop` |
| `home` | `~/` |
| `actual` / `cwd` | Current working directory |

> ✅ Aliases work in **both Spanish and English** — auto-detected based on your system locale.

---

## 📊 Port Presets

| Preset | Ports | Best for |
|--------|-------|----------|
| `pivot` | 35 key ports | Fast pivot-focused scan |
| `top50` | 50 common ports | General recon |
| `top100` | 1024 + extras | Thorough scan |
| `all` | 1–9999 | Full coverage (slow) |

---

## 🔍 Pivot Detection

PIVOTX automatically identifies pivot opportunities per host:

| Host Type | Detected By | Suggested Methods |
|-----------|-------------|-------------------|
| Linux/SSH | Port 22 | `ssh -D` SOCKS5, Chisel, Ligolo-ng |
| Domain Controller | Ports 88, 389 | Kerberoasting, Pass-the-Hash |
| Windows Host | Ports 445, 135 | SMB/PsExec, WMIExec, evil-winrm |
| Network Device | Ports 23, 161 | Telnet, SNMP enum |
| Database | Ports 3306, 1433, 6379 | UDF injection, xp_cmdshell, RCE |
| Web Server | Ports 80, 443, 8080 | Web shell, reverse shell |

---

## 📄 Report Features

The generated HTML report includes:

- **Header** with target network, scan date, duration, % of network scanned, and most vulnerable host
- **8 metric cards** — total hosts, critical/high/medium/low risk counts, SSH/SMB/RDP exposure
- **Interactive network map** — drag nodes, hover for details, color-coded by risk
- **Port frequency bar chart** — top 10 ports found across the network
- **Host registry table** — expandable rows with banner grabs and copy-paste commands
- **Suggested pivot chain** — top 5 hosts ranked by pivot score

---

## 🛠️ How It Works

```
Phase 1 — Discovery     ARP sweep (root) or Ping sweep
Phase 2 — Port Scan     Multithreaded TCP connect scan + banner grab
Phase 3 — Analysis      Risk scoring, role classification, pivot method detection
Phase 4 — Report        Interactive HTML with charts and network map
```

---

## 📦 Installation

```bash
git clone https://github.com/YOUR_USERNAME/pivotx.git
cd pivotx
pip3 install -r requirements.txt
sudo python3 pivotx.py -n 192.168.1.0/24
```

---

## ⚠️ Legal Disclaimer

> **PIVOTX is intended for authorized security testing and educational purposes only.**
> 
> Only use this tool on networks you own or have explicit written permission to test.
> Unauthorized network scanning may be illegal in your jurisdiction.
> The author assumes no liability for misuse.

---

## 🤝 Contributing

Contributions are welcome! Feel free to:

- 🐛 Report bugs via [Issues](../../issues)
- 💡 Suggest features via [Issues](../../issues)
- 🔧 Submit pull requests

---

## 📝 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

Made with 🔥 for the infosec community

⭐ **If PIVOTX helped you, please give it a star!** ⭐

</div>
