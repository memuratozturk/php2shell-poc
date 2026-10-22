#!/usr/bin/env python3
"""
PHP2Shell Recon — Hedef PHP sunucusunu fingerprint eder (exploit calistirmadan).

    python3 tools/recon.py -u http://target.com
    python3 tools/recon.py -u https://target.com -k --timeout 15

Cikti: JSON formatinda vuln raporu.
"""

import argparse
import json
import re
import socket
import ssl
import sys
import time
import urllib.parse
from typing import Any, Dict, Optional, Tuple


# ==========================================================================
# HTTP UTILITIES
# ==========================================================================

def _build_socket(host: str, port: int, timeout: float,
                  insecure: bool, https: bool) -> socket.socket:
    """TCP (veya TLS) socket olustur."""
    sock = socket.create_connection((host, port), timeout)
    if https:
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _recv_all(sock: socket.socket, limit: int = 1 << 17) -> bytes:
    """Socket'ten tum veriyi oku."""
    chunks = []
    total = 0
    while True:
        chunk = sock.recv(8192)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total >= limit:
            break
    return b"".join(chunks)


def http_request(host: str, port: int, method: str = "GET",
                 path: str = "/", headers: Optional[Dict[str, str]] = None,
                 body: Optional[bytes] = None, timeout: float = 10.0,
                 https: bool = False,
                 insecure: bool = False) -> Tuple[int, dict, bytes]:
    """Minimal HTTP istegi — harici bagimlillik yok."""
    sock = None
    try:
        sock = _build_socket(host, port, timeout, insecure, https)

        hdr_lines = [f"{method} {path} HTTP/1.1", f"Host: {host}",
                      "Connection: close",
                      "User-Agent: Mozilla/5.0 (compatible; recon)"]
        if headers:
            for k, v in headers.items():
                hdr_lines.append(f"{k}: {v}")
        if body is not None:
            hdr_lines.append(f"Content-Length: {len(body)}")

        raw = "\r\n".join(hdr_lines) + "\r\n\r\n"
        sock.sendall(raw.encode())
        if body:
            sock.sendall(body)

        response = _recv_all(sock)
        parts = response.split(b"\r\n\r\n", 1)
        head = parts[0].decode("latin1", errors="replace")
        resp_body = parts[1] if len(parts) > 1 else b""

        status_m = re.search(r"HTTP/[\d.]+ (\d+)", head)
        status = int(status_m.group(1)) if status_m else 0

        resp_headers: Dict[str, str] = {}
        for line in head.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                resp_headers[k.strip().lower()] = v.strip()

        return status, resp_headers, resp_body
    except Exception as e:
        return 0, {}, str(e).encode()
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


# ==========================================================================
# FINGERPRINT
# ==========================================================================

_PATCHED_VERSIONS: Dict[str, int] = {
    "8.2": 35,
    "8.3": 36,
    "8.4": 27,
    "8.5": 12,
}


def _parse_version(ver: str) -> Tuple[int, int, int]:
    try:
        parts = ver.split(".")
        return int(parts[0]), int(parts[1]), int(parts[2]) if len(parts) > 2 else 0
    except (ValueError, IndexError):
        return 0, 0, 0


def _detect_php_version(headers: dict) -> str:
    """X-Powered-By veya Server header'indan PHP surumunu cek."""
    for key in ("x-powered-by", "server"):
        val = headers.get(key, "")
        m = re.search(r"PHP[/\s]*([\d.]+)", val, re.I)
        if m:
            return m.group(1)
    return "unknown"


def _detect_sapi(headers: dict) -> str:
    """SAPI tipini tespit et (mod_php / FPM / CGI)."""
    powered = headers.get("x-powered-by", "").lower()
    server = headers.get("server", "").lower()

    if "fpm" in powered:
        return "fpm"
    if "cgi" in powered:
        return "cgi"
    if "apache" in server and "php" in server:
        return "mod_php"
    if "apache" in server and "php" in powered:
        return "mod_php"
    if "nginx" in server and "php" in powered:
        return "fpm"
    if "php" in powered:
        return "likely_mod_php"
    return "unknown"


def _detect_server(headers: dict) -> str:
    return headers.get("server", "unknown")


def _detect_os(headers: dict) -> str:
    """Server header'indan OS tahmini."""
    server = headers.get("server", "").lower()
    if "debian" in server or "ubuntu" in server:
        return "Debian/Ubuntu"
    if "centos" in server or "red hat" in server or "rhel" in server:
        return "RHEL/CentOS"
    if "win" in server:
        return "Windows"
    if "unix" in server or "linux" in server:
        return "Linux"
    return "unknown"


def _test_upload_progress(host: str, port: int, path: str,
                          timeout: float, https: bool,
                          insecure: bool) -> str:
    """session.upload_progress durumunu test POST ile kontrol et."""
    boundary = "----php2shellRecon"
    body_parts = [
        f"--{boundary}",
        'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"',
        "",
        "php2shell_probe",
        f"--{boundary}",
        'Content-Disposition: form-data; name="file"; filename="probe.txt"',
        "Content-Type: text/plain",
        "",
        "x",
        f"--{boundary}--",
    ]
    body = "\r\n".join(body_parts).encode()

    hdrs = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Cookie": "PHPSESSID=php2shellrecon",
    }

    status, resp_headers, resp_body = http_request(
        host, port, method="POST", path=path, headers=hdrs,
        body=body, timeout=timeout, https=https, insecure=insecure,
    )

    if status == 0:
        return "error"

    # Set-Cookie ile session baslatildiysa upload_progress enabled
    set_cookie = resp_headers.get("set-cookie", "")
    if "PHPSESSID" in set_cookie:
        return "enabled"

    # WAF / ModSecurity block
    if status in (403, 406, 418):
        return "blocked_by_waf"

    return "unknown"


def _detect_memory_limit(headers: dict, body: bytes) -> str:
    """phpinfo ciktisi varsa memory_limit'i cek."""
    text = body.decode("latin1", errors="replace")
    m = re.search(r"memory_limit.*?<td[^>]*>([^<]+)", text, re.I | re.S)
    if m:
        return m.group(1).strip()
    return "unknown"


def _assess_vulnerability(php_version: str, sapi: str) -> Dict[str, Any]:
    """Vuln degerlendirmesi — version + SAPI bazli."""
    major, minor, patch = _parse_version(php_version)

    result: Dict[str, Any] = {
        "vulnerable": False,
        "exploitable": False,
        "verdict": "",
        "fix": "",
    }

    if php_version == "unknown":
        result["verdict"] = "PHP version could not be determined"
        return result

    if major < 8:
        result["verdict"] = "NOT AFFECTED — PHP 7.x is not vulnerable"
        return result

    branch = f"{major}.{minor}"
    patch_ver = _PATCHED_VERSIONS.get(branch)

    if patch_ver is None:
        if major == 8 and minor <= 1:
            result["vulnerable"] = True
            result["verdict"] = f"VULNERABLE — PHP {branch}.x is EOL, no fix available"
        else:
            result["verdict"] = f"Unknown branch {branch}"
        return result

    if patch >= patch_ver:
        result["verdict"] = f"PATCHED — {branch}.{patch} >= {branch}.{patch_ver}"
        result["fix"] = f"Already on {branch}.{patch}"
        return result

    result["vulnerable"] = True
    result["fix"] = f"Update to PHP {branch}.{patch_ver}+"

    sapi_lower = sapi.lower()
    if sapi_lower in ("mod_php", "likely_mod_php"):
        result["exploitable"] = True
        result["verdict"] = f"VULNERABLE — update to PHP {branch}.{patch_ver}+"
    elif "fpm" in sapi_lower:
        result["verdict"] = (
            f"Version vulnerable ({branch}.{patch}) but PHP-FPM "
            "prevents exploitation"
        )
    else:
        result["verdict"] = (
            f"Version vulnerable ({branch}.{patch}), SAPI unknown — "
            "manual check required"
        )

    return result


# ==========================================================================
# MAIN
# ==========================================================================

BANNER = r"""
 ____  _   _ ____  ____    _          _ _   ____                      
|  _ \| | | |  _ \|___ \  | |        | | | |  _ \ ___  ___ ___  _ __  
| |_) | |_| | |_) | __) |_| |__   ___| | | | |_) / _ \/ __/ _ \| '_ \ 
|  __/|  _  |  __/ / __/|_   __| / _ \ | | |  _ <  __/ (_| (_) | | | |
|_|   |_| |_|_|   |_____|_|_|    \___|_|_| |_| \_\___|\___\___/|_| |_|

  PHP2Shell Recon v1.0 — Exploit-free fingerprinting
"""


def run_recon(url: str, timeout: float = 10.0,
              insecure: bool = False) -> Dict[str, Any]:
    """Tam recon calistir, JSON-serialisable dict dondur."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    https = parsed.scheme == "https"
    port = parsed.port or (443 if https else 80)
    path = parsed.path or "/"

    report: Dict[str, Any] = {
        "target": url,
        "host": host,
        "port": port,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # 1) HTTP GET — header toplama
    status, headers, body = http_request(
        host, port, path=path, timeout=timeout, https=https, insecure=insecure,
    )

    if status == 0:
        report["error"] = "Connection failed"
        return report

    report["http_status"] = status
    report["php_version"] = _detect_php_version(headers)
    report["sapi"] = _detect_sapi(headers)
    report["server"] = _detect_server(headers)
    report["os"] = _detect_os(headers)
    report["memory_limit"] = _detect_memory_limit(headers, body)

    # 2) session.upload_progress probe
    report["upload_progress"] = _test_upload_progress(
        host, port, path, timeout, https, insecure,
    )

    # 3) Vulnerability assessment
    assessment = _assess_vulnerability(report["php_version"], report["sapi"])
    report["assessment"] = assessment

    return report


def _print_report(r: Dict[str, Any]) -> None:
    """Insan-okunur cikti."""
    print(f"[*] Target: {r['target']}")

    if "error" in r:
        print(f"[-] Error: {r['error']}")
        return

    sapi_str = r.get("sapi", "?")
    server_str = r.get("server", "?")
    os_str = r.get("os", "")
    os_part = f", {os_str}" if os_str and os_str != "unknown" else ""

    php_ver = r.get("php_version", "unknown")
    print(f"[+] PHP {php_ver} ({sapi_str}, {server_str}{os_part})")

    up = r.get("upload_progress", "unknown")
    if up == "enabled":
        print(f"[+] session.upload_progress: enabled")
    elif up == "blocked_by_waf":
        print(f"[~] session.upload_progress: blocked by WAF/ModSecurity")
    else:
        print(f"[~] session.upload_progress: {up}")

    mem = r.get("memory_limit", "unknown")
    if mem != "unknown":
        print(f"[+] memory_limit: {mem}")

    assessment = r.get("assessment", {})
    verdict = assessment.get("verdict", "")

    if assessment.get("exploitable"):
        print(f"[!] VULNERABLE — {assessment.get('fix', verdict)}")
    elif assessment.get("vulnerable"):
        print(f"[~] {verdict}")
    else:
        print(f"[*] {verdict}")


def main() -> int:
    print(BANNER)

    ap = argparse.ArgumentParser(
        description="PHP2Shell Recon — Exploit-free target fingerprinting",
    )
    ap.add_argument("-u", "--url", required=True, help="Target URL")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="HTTP timeout (default: 10s)")
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="Skip TLS certificate verification")
    ap.add_argument("--json", action="store_true",
                    help="JSON-only output (no banner)")
    args = ap.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    report = run_recon(url, timeout=args.timeout, insecure=args.insecure)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_report(report)
        print(f"\n[*] Full JSON:\n{json.dumps(report, indent=2)}")

    if report.get("assessment", {}).get("exploitable"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
