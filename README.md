# recon-scan.sh — Automated Recon & Vulnerability Scanner (Kali)

A single-target automation wrapper that chains the standard Kali tools through
six phases — recon → enumeration → vulnerability **scanning** — and prints a
comprehensive, colored digest to your terminal while saving all raw output to a
timestamped folder.

> **Authorized testing only.** Run this **only** against systems you own or have
> explicit written permission to test. Unauthorized scanning is illegal.
>
> **Detection only — by design.** It does **not** exploit, brute-force
> credentials, or send DoS/stress traffic, even in `--aggressive` mode. It is a
> recon/scan aggregator, not an attack tool.

---

## 1. Requirements

Kali Linux (or any distro with the tools below). Missing tools are **skipped**
automatically with an install hint, so it still runs on a partial setup.

Recommended packages:

```bash
sudo apt update
sudo apt install -y nmap nikto whatweb seclists ffuf feroxbuster \
                    dnsutils whois curl wpscan
# Go-based tools (nuclei / subfinder / httpx) — via apt or official installers:
sudo apt install -y nuclei subfinder httpx-toolkit
# optional API helpers:
sudo apt install -y arjun           # kiterunner (kr) is a manual install
```

| Phase uses | Tools |
|---|---|
| Recon | `whois`, `dig` (dnsutils), `subfinder`, `httpx`, `whatweb` |
| Ports | `nmap`, `searchsploit` |
| Content | `feroxbuster` / `ffuf` / `gobuster`, `seclists` |
| Web vuln | `nikto`, `nuclei`, `wpscan` |
| TLS | `testssl.sh` / `sslscan` / `nmap` |
| API | `curl`, `ffuf`, `nuclei`, optional `arjun` / `kr` |

---

## 2. Install

```bash
chmod +x recon-scan.sh
```

---

## 3. Usage

```bash
./recon-scan.sh <ip|domain|url> [--full] [--aggressive] [--verbose]
```

The target can be an **IP**, **domain**, or **full URL** — it's parsed into a
host (for network tools) and a URL (for web tools) automatically.

### Basic

```bash
./recon-scan.sh http://testphp.vulnweb.com        # web target
./recon-scan.sh example.com                        # bare domain
./recon-scan.sh 10.10.10.5                          # IP
```

### Modes

| Mode | Flag | What it does |
|---|---|---|
| Balanced | *(default)* | nmap top-1000 ports, standard web scans. Fast. |
| Full ports | `--full` | nmap all 65535 TCP ports; forces TLS phase. |
| Aggressive | `--aggressive` / `-A` | Deep + **noisy** detection: `nmap -A -p-`, vuln NSE (no dos/exploit/brute), UDP top-50, larger wordlist + recursion, all-severity nuclei, deeper wpscan. Implies `--full`. |

```bash
./recon-scan.sh 10.10.10.5 --full
./recon-scan.sh https://app.example.com --aggressive
```

> Aggressive mode is loud and will trigger IDS/IPS and load the target — use it
> on systems you control (e.g. a local lab) or within an agreed test window.

### Flags

| Flag | Meaning |
|---|---|
| `--full` | All TCP ports. |
| `--aggressive`, `-A` | Deep detection (implies `--full`). |
| `--verbose`, `-v` | Stream the **full** raw output of each tool to the terminal (default shows a digest). |
| `-h`, `--help` | Show the header/usage and exit. |

```bash
./recon-scan.sh http://testphp.vulnweb.com --verbose
./recon-scan.sh http://localhost:3000 --aggressive --verbose
```

---

## 4. The six phases

1. **Recon & fingerprint** — whois, DNS, subdomain discovery (subfinder → httpx live check), tech fingerprint (whatweb).
2. **Ports & services** — nmap service/version + scripts; searchsploit version matching from the nmap XML; NSE vuln scripts in aggressive mode.
3. **Web content discovery** — directory/file brute via feroxbuster/ffuf/gobuster against a SecLists wordlist.
4. **Web vulnerability scan** — nikto + nuclei; wpscan (passive) auto-runs if WordPress is detected.
5. **TLS / SSL** — testssl.sh / sslscan / nmap ssl-enum-ciphers (on https or with `--full`).
6. **API discovery & testing** — probes common API/doc/spec paths, detects GraphQL introspection, ffuf API-route discovery, optional arjun/kiterunner, and a focused nuclei `api,swagger,graphql,exposure` run.

---

## 5. Output

Each run creates a folder:

```
recon_<host>_<timestamp>/
├── SUMMARY.md            # consolidated summary (markdown)
├── whois.txt  dns.txt  subdomains.txt  live-subs.txt  whatweb.txt
├── nmap.txt   nmap.xml  nmap-udp.txt   searchsploit.txt
├── content.txt (or content.csv)
├── nikto.txt  nuclei.txt  wpscan.txt
├── testssl.txt / sslscan.txt / ssl-ciphers.txt
└── api-endpoints.txt  graphql-introspection.txt  api-routes.csv  nuclei-api.txt
```

**On screen** you get a colored, per-phase digest (open ports in green, critical/
high findings in red, API endpoints in magenta) and a final **SCAN REPORT** with
counts and the file list. Use `--verbose` for the full raw stream instead of the
digest.

**Logging** — colors auto-disable when piped, so this stays clean:

```bash
./recon-scan.sh http://testphp.vulnweb.com | tee scan.log
```

---

## 6. Practice targets (sanctioned)

Public test sites (light use only — don't hammer shared servers):

```bash
./recon-scan.sh http://testphp.vulnweb.com       # web (Acunetix)
./recon-scan.sh http://rest.vulnweb.com          # REST API
./recon-scan.sh scanme.nmap.org --full           # nmap (Nmap project)
```

Local labs (best for `--aggressive` and API testing — full authorization):

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop   # ./recon-scan.sh http://localhost:3000 --aggressive
docker run -d -p 5000:5000 erev0s/vampi            # ./recon-scan.sh http://localhost:5000     (API)
docker run -d -p 5013:5013 -e WEB_HOST=0.0.0.0 dolevf/dvga   # GraphQL introspection
docker run -d -p 8080:80   vulnerables/web-dvwa    # ./recon-scan.sh http://localhost:8080 --full
```

---

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| "skipped: 'X' not installed" | Install the tool (hint shown), or ignore — the phase is optional. |
| No content discovered | Install `seclists` (`sudo apt install seclists`). |
| TLS phase skipped | Target is `http://`; use an `https://` URL or add `--full`. |
| nuclei/subfinder not found | Install the Go tools (apt `nuclei`/`subfinder` or official installers). |
| Output looks colorless in a file | Expected — colors auto-disable when not a terminal. |

---

## 8. Responsible use

This tool performs reconnaissance and vulnerability **scanning** only. Validate
any finding manually (e.g. in Burp Suite), and perform exploitation only inside
an authorized lab or engagement with written scope. For aggressive scans of
production-like systems, notify the SOC/owner first — the traffic is loud by
design.
