# Threat Detection Guide

How to detect php2shell exploitation attempts on your servers.

## Behavioral Indicators

After successful exploitation, PHP worker processes spawn unexpected child processes. Monitor for these:

### Suspicious Child Processes

| Category | Commands |
|----------|----------|
| Shells | `/bin/sh`, `/bin/bash`, `cmd.exe`, `powershell.exe` |
| Interpreters | `python`, `perl`, `ruby` |
| Network tools | `curl`, `wget`, `nc`, `ncat`, `certutil.exe` |
| Reverse shell patterns | `/dev/tcp/`, `fsockopen`, `mkfifo` |
| Recon commands | `whoami`, `id`, `uname -a`, `ipconfig`, `hostname` |

### What to Monitor

Parent process should be `apache2`, `httpd`, `php-fpm`, or `php-cgi`. Any of the commands above spawned as a child of these processes is a strong indicator.

## Network-Level Detection

### Multipart POST Anomalies

The exploit uses oversized multipart POST requests (12MB+) to trigger OOM:

- POST body > 8MB to a page that should not receive file uploads
- `PHP_SESSION_UPLOAD_PROGRESS` field in multipart body
- Multiple rapid multipart POSTs to the same endpoint
- Chunked transfer encoding with no `Content-Length` header

### Session Cookie Anomalies

Memory disclosure leaks heap data through `Set-Cookie: PHPSESSID`:

- `PHPSESSID` value longer than ~40 characters (normal is 26–32)
- Binary/non-printable characters in URL-encoded cookie value
- Cookie value containing memory pointers (e.g., `%00%00%7f`)

## Log Patterns

### Apache Access Log

```
# Rapid repeated POSTs to the same endpoint (worker rotation + exploit stages)
grep -P 'POST .+\.php.* (200|500)' /var/log/apache2/access.log | \
    awk '{print $1, $4}' | uniq -c | sort -rn | head -20
```

### PHP Error Log

```
# OOM errors (exploit trigger)
grep -i "allowed memory size.*exhausted" /var/log/php*.log

# Fatal errors followed by immediate new requests
grep -i "fatal error" /var/log/php*.log
```

### Process Monitoring (Linux)

```bash
# Watch for suspicious child processes of web server
ps -eo pid,ppid,user,args | grep -E '(apache2|httpd|php)' | \
    grep -vE '(apache2|httpd|php-fpm|grep)'

# Real-time monitoring
watch -n 1 'ps --forest -eo pid,ppid,user,args | grep -A2 apache2'
```

For automated monitoring, consider [process-watcher](https://github.com/Neo23x0/process-watcher) by Florian Roth.

## YARA Rule

```yara
rule PHP2Shell_Multipart_Payload {
    meta:
        description = "Detects php2shell exploit multipart payload"
        author = "memuratozturk"
        reference = "CVE-2026-109618 / CVE-2026-109619"
    strings:
        $s1 = "PHP_SESSION_UPLOAD_PROGRESS" ascii
        $s2 = "attacksessionid" ascii nocase
        $s3 = "multipart/form-data" ascii nocase
        $hex_forge = { 01 00 00 00 07 00 00 00 10 00 00 00 F8 FF FF FF }
    condition:
        $s1 and ($s2 or $s3) and #s1 > 1
}
```

## Snort/Suricata Rule

```
alert http any any -> $HOME_NET any (
    msg:"PHP2Shell CVE-2026-109619 exploit attempt";
    flow:to_server,established;
    content:"PHP_SESSION_UPLOAD_PROGRESS"; nocase;
    content:"multipart/form-data"; nocase; http_header;
    threshold:type both, track by_src, count 3, seconds 10;
    classtype:web-application-attack;
    sid:2026109619; rev:1;
)
```

## Incident Response

If you detect exploitation:

1. **Isolate** the affected host immediately
2. **Preserve** Apache/PHP logs and `/tmp` contents
3. **Check** for dropped webshells in web roots
4. **Review** `/tmp`, `/var/tmp`, `/dev/shm` for temp files
5. **Check** crontab and systemd timers for persistence
6. **Update** PHP to a patched version before bringing back online
