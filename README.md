<div align="center">
  <h1>Oculi Vulnerability Scanner</h1>
  <p><strong>A blazingly fast, ZERO-dependency, multithreaded vulnerability scanner and Exploit-DB linker.</strong></p>

  <img src="assets/oculi_app_icon.png" alt="Oculi Minimalist Logo" width="200"/>

  <p>
    <a href="#features">Features</a> •
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a> •
    <a href="#comparison">Comparison</a> •
    <a href="#roadmap">Roadmap</a>
  </p>
</div>

---

## ⚡ Overview
Oculi is a lightweight, aggressive, ZERO-dependency, multi-threaded vulnerability scanner written purely in Python. It detects open ports, actively probes for precise service banners, and automatically cross-references those banners against a locally cached copy of the [Exploit Database](https://www.exploit-db.com/) to instantly highlight potential vulnerabilities, CVEs, and proof-of-concept exploit code.

## ✨ Features
* **Zero Dependencies**: Pure standard library Python 3. Runs out of the box.
* **Aggressive Multithreading**: Capable of scanning thousands of ports simultaneously.
* **Smart Banner Grabbing**: Employs stealth probes to coax banners out of hesitant HTTP/HTTPS services, while also understanding raw SSH and FTP banners.
* **Exploit-DB Integration**: Downloads and caches the Exploit-DB registry.
* **Intelligent Version Math**: Parses complex version constraints from Exploit-DB descriptions (e.g., `Apache >= 2.2.0 < 2.4.29` or `1.1.x - 1.5.0`) to avoid false positives.
* **Beautiful CLI Reports**: Provides organized, colorized terminal output and structural file-saving capabilities.

## 🚀 Installation
Because Oculi only uses standard Python libraries, installation is incredibly simple.

```bash
# Clone the repository
git clone https://github.com/GoSlowPoke168/Oculi.git
cd Oculi

# Update the exploit database before first run
python oculi.py -

# Optionally, setup a symlink for the command
chmod +x oculi.py
ln -s $(pwd)/oculi.py /usr/local/bin/oculi
```

## 💻 Usage
Run `oculi.py` with standard arguments to begin an automated scan.

```bash
# Basic Scan (Scans default Top 1000 ports at Speed 3)
python oculi.py -t http://example.com

# Target Specific Ports and Output Report
python oculi.py -t 192.168.1.15 -p 22,80,443,8080 -o report.txt

# Aggressive Scan (All 65535 ports at maximum Speed 5)
python oculi.py -t 10.0.0.5 -p - -s 5
```

### Options
| Flag | Description |
| ---- | ----------- |
| `-t`, `--target` | **[Required]** Target IP Address or Hostname |
| `-p`, `--ports` | Ports to scan: `-p 80,443`, `-p 1-100`, or `-p-` for all ports. Defaults to Nmap's Top 1000. |
| `-s`, `--speed` | Scan Speed (1-5), where 5 is maximum throttle. Default: 3. |
| `-o`, `--output` | Save the detailed scan report out to a plain text file. |
| `-u`, `--update` | Updates the Exploit-DB JSON cache from the official GitLab repo. |

## 📸 Demo
<div align="center">
  <img src="assets/Oculi-Demo.gif" alt="Oculi Scanning Demo GIF" width="800"/>
  <p><em>Example showing Oculi rapidly discovering multiple open ports and exploits.</em></p>
</div>

## ⚖️ Comparison
How does Oculi compare to established tools?

| Feature | Oculi | Nmap (Default) | RustScan | SearchSploit |
| :--- | :---: | :---: | :---: | :---: |
| **Footprint / Dependencies** | **None (Pure Python)** | Heavy (Nmap) | Needs Rust/Docker | None (Bash) |
| **Raw Scanning Speed** | 🚀 Fast | 🐢 Slower (Heuristic) | **⚡ Unbeatable** | N/A |
| **Fingerprinting Accuracy** | 🟡 Basic (Banner Grabbing) | **🟢 Phenomenal (TCP/IP)** | 🟢 Excellent (Nmap Wrapper) | N/A |
| **Exploit Database Integration** | **🟢 Yes (Automated)** | 🔴 No | 🔴 No | 🟢 Yes (Manual) |
| **Version Math Parsing** | **🟢 Yes (Range Evaluation)** | 🔴 No | 🔴 No | 🔴 No (Basic String Match) |
| **Best Use Case** | Quick reconnaissance & immediate exploit discovery. | Deep network mapping & exact OS fingerprinting. | Blindly finding open ports extremely quickly. | Offline exploit lookups. |

> **Why reinvent the wheel with SearchSploit?** 
> SearchSploit relies heavily on basic `grep` text matching. Oculi improves upon SearchSploit's search engine by implementing **True Version Math**. It parses relational ranges like "Apache >= 2.2.0 < 2.4.29" within the database, dynamically preventing false-positive exploit returns when you scan a patched host.

## 🗺️ Roadmap / TODO
- [ ] Implement an **Nmap Wrapper Integration** mode to ingest highly accurate Nmap XML scans and run them through Oculi's Exploit-DB parsing engine.

## ⚠️ Disclaimer
Oculi was developed for educational purposes, Capture-the-Flag (CTF) events, and authorized penetration testing only. Do not use this tool against infrastructure you do not own or have explicit permission to test.
