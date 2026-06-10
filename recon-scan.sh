#!/usr/bin/env bash
###############################################################################
# recon-scan.sh  —  one-target automated recon & vulnerability scan (Kali)
#
# Recon -> enumeration -> vulnerability SCANNING (detection only).
# NO exploitation, NO credential brute-forcing, NO DoS — even in --aggressive.
#
# MODES:   (default) balanced | --full (all TCP ports) | --aggressive (-A)
# OUTPUT:  comprehensive colored digest on screen + raw files in recon_<host>_<ts>/
# FLAGS:   --verbose  also stream full raw tool output to the terminal
#
# USAGE:   ./recon-scan.sh <ip|domain|url> [--full] [--aggressive] [--verbose]
# RUN ON:  Kali Linux (missing tools are skipped with a hint).
###############################################################################
set -uo pipefail

# ---------- args ----------
[[ $# -lt 1 ]] && { echo "Usage: $0 <ip|domain|url> [--full] [--aggressive] [--verbose]"; exit 1; }
RAW=""; FULL=""; AGGR=""; VERBOSE=""
for a in "$@"; do case "$a" in
    --full)          FULL="yes" ;;
    --aggressive|-A) AGGR="yes"; FULL="yes" ;;
    --verbose|-v)    VERBOSE="yes" ;;
    -h|--help)       sed -n '2,18p' "$0"; exit 0 ;;
    *)               [[ -z "$RAW" ]] && RAW="$a" ;;
esac; done
[[ -z "$RAW" ]] && { echo "No target. Usage: $0 <ip|domain|url> [--full] [--aggressive] [--verbose]"; exit 1; }

# ---------- parse target ----------
if [[ "$RAW" =~ ^https?:// ]]; then
    URL="$RAW"; HOST="$(echo "$RAW" | sed -E 's#^https?://##; s#/.*$##; s#:.*$##')"
    SCHEME="$(echo "$RAW" | grep -oE '^https?')"
else
    HOST="$(echo "$RAW" | sed -E 's#/.*$##; s#:.*$##')"; SCHEME="http"; URL="http://${HOST}"
fi
[[ "$HOST" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && IS_IP="yes" || IS_IP="no"
MODE="balanced"; [[ -n "$FULL" ]] && MODE="full-ports"; [[ -n "$AGGR" ]] && MODE="aggressive"
BASE="${SCHEME}://${HOST}"

# ---------- colors (auto-off if not a terminal) ----------
if [[ -t 1 ]]; then
    R=$'\e[0m'; B=$'\e[1m'; DIM=$'\e[2m'; RED=$'\e[31m'; GRN=$'\e[32m'
    YEL=$'\e[33m'; BLU=$'\e[34m'; CYN=$'\e[36m'; MAG=$'\e[35m'
else R=""; B=""; DIM=""; RED=""; GRN=""; YEL=""; BLU=""; CYN=""; MAG=""; fi

# ---------- output dir ----------
START=$(date +%s); TS="$(date +%Y%m%d-%H%M%S)"
OUT="recon_${HOST}_${TS}"; mkdir -p "$OUT"; SUMMARY="${OUT}/SUMMARY.md"
{ echo "# Recon & Scan — ${HOST}"; echo "_URL:_ ${URL} · _Mode:_ ${MODE} · _Started:_ $(date)"; echo; } > "$SUMMARY"

# ---------- helpers ----------
have(){ command -v "$1" >/dev/null 2>&1; }
cnt(){ [[ -s "$1" ]] && wc -l < "$1" 2>/dev/null || echo 0; }
hr(){   printf "${DIM}%s${R}\n" "------------------------------------------------------------"; }
sec(){  printf "\n${B}${CYN}══[ %s ]%s${R}\n" "$1" "$(printf '═%.0s' $(seq 1 $((50-${#1}))))"; echo -e "\n## $1" >> "$SUMMARY"; }
info(){ printf "   ${DIM}%s${R}\n" "$1"; }
ok(){   printf "   ${GRN}✔${R} %s\n" "$1"; echo "- ✔ $1" >> "$SUMMARY"; }
warn(){ printf "   ${YEL}!${R} %s\n" "$1"; echo "- ! $1" >> "$SUMMARY"; }
hit(){  printf "   ${RED}${B}➜ %s${R}\n" "$1"; echo "- ➜ $1" >> "$SUMMARY"; }
skip(){ printf "   ${DIM}— skipped: %s${R}\n" "$1"; echo "- (skipped) $1" >> "$SUMMARY"; }
# show file content to terminal: full if --verbose, else first N lines
showf(){ local f="$1" n="${2:-12}"; [[ -s "$f" ]] || return
    if [[ -n "$VERBOSE" ]]; then sed 's/^/      /' "$f"
    else sed 's/^/      /' "$f" | head -n "$n"; local t; t=$(wc -l < "$f"); [[ "$t" -gt "$n" ]] && printf "      ${DIM}... (%s more lines in %s)${R}\n" "$((t-n))" "$f"; fi; }

# ---------- header ----------
clear 2>/dev/null || true
printf "${B}${BLU}"
echo "============================================================"
echo "  RECON & VULN SCAN   (authorized testing only)"
echo "============================================================${R}"
printf "  ${B}Target${R} : %s\n  ${B}URL${R}    : %s\n  ${B}Type${R}   : %s\n  ${B}Mode${R}   : %s%s\n  ${B}Output${R} : %s/\n" \
    "$HOST" "$URL" "$([[ $IS_IP == yes ]] && echo IP || echo domain)" "$MODE" "$([[ -n $VERBOSE ]] && echo ' + verbose')" "$OUT"
[[ -n "$AGGR" ]] && printf "  ${YEL}${B}AGGRESSIVE: loud, will trip IDS/IPS, loads target (detection only).${R}\n"
hr

# ============================================================ PHASE 1
sec "Phase 1 — Recon & fingerprint"
if have whois; then whois "$HOST" > "${OUT}/whois.txt" 2>&1
    org=$(grep -iE 'OrgName|org-name|registrar:' "${OUT}/whois.txt" | head -1 | sed 's/^[^:]*://;s/^ *//')
    [[ -n "$org" ]] && ok "whois: ${org}" || ok "whois -> whois.txt"; else skip "whois"; fi
if [[ "$IS_IP" == no ]] && have dig; then
    ( dig +noall +answer "$HOST" A; dig +noall +answer "$HOST" mx; dig +short txt "$HOST" ) > "${OUT}/dns.txt" 2>&1
    ip=$(dig +short "$HOST" | head -1); ok "DNS A record: ${ip:-n/a}"; showf "${OUT}/dns.txt" 6; fi
if [[ "$IS_IP" == no ]] && have subfinder; then
    subfinder -d "$HOST" -silent > "${OUT}/subdomains.txt" 2>/dev/null
    c=$(cnt "${OUT}/subdomains.txt"); ok "subdomains found: ${c}"
    if have httpx && [[ "$c" -gt 0 ]]; then
        httpx -silent -title -tech-detect -status-code < "${OUT}/subdomains.txt" > "${OUT}/live-subs.txt" 2>/dev/null
        ok "live subdomains: $(wc -l < "${OUT}/live-subs.txt")"; showf "${OUT}/live-subs.txt" 10; fi
fi
if have whatweb; then whatweb -a 3 --color=never "$URL" > "${OUT}/whatweb.txt" 2>&1
    ok "tech fingerprint:"; showf "${OUT}/whatweb.txt" 4; else skip "whatweb"; fi

# ============================================================ PHASE 2
sec "Phase 2 — Ports & services (nmap)"
if have nmap; then
    if [[ -n "$AGGR" ]]; then
        info "nmap -A -p- -T4  + vuln NSE (no dos/exploit/brute)"
        nmap -A -p- -T4 --script "(default or vuln) and not (dos or exploit or brute)" \
             -oN "${OUT}/nmap.txt" -oX "${OUT}/nmap.xml" "$HOST" >/dev/null 2>&1
        nmap -sU --top-ports 50 -T4 -oN "${OUT}/nmap-udp.txt" "$HOST" >/dev/null 2>&1
    else
        P="--top-ports 1000"; [[ -n "$FULL" ]] && P="-p-"; info "nmap -sV -sC -T4 ${P}"
        nmap -sV -sC -T4 $P -oN "${OUT}/nmap.txt" -oX "${OUT}/nmap.xml" "$HOST" >/dev/null 2>&1
    fi
    opens=$(grep -E "^[0-9]+/(tcp|udp) +open" "${OUT}/nmap.txt" 2>/dev/null)
    if [[ -n "$opens" ]]; then
        ok "open ports / services:"
        echo "$opens" | sed 's/^/      /' | while read -r l; do printf "      ${GRN}%s${R}\n" "${l#      }"; done
        echo "$opens" >> "$SUMMARY"
    else warn "no open ports in scanned range"; fi
    [[ -s "${OUT}/nmap-udp.txt" ]] && { u=$(grep -E "open" "${OUT}/nmap-udp.txt" | grep -v "open|filtered" | wc -l); info "UDP open (top-50): ${u} -> nmap-udp.txt"; }
    if grep -qiE 'VULNERABLE|CVE-' "${OUT}/nmap.txt" 2>/dev/null; then
        hit "nmap NSE flagged possible vulnerabilities:"; grep -iE 'VULNERABLE|CVE-' "${OUT}/nmap.txt" | sed 's/^/      /' | head -8; fi
    if have searchsploit && [[ -s "${OUT}/nmap.xml" ]]; then
        searchsploit --nmap "${OUT}/nmap.xml" > "${OUT}/searchsploit.txt" 2>/dev/null
        m=$(grep -cE '\|' "${OUT}/searchsploit.txt" 2>/dev/null || echo 0)
        [[ "$m" -gt 0 ]] && { hit "searchsploit version matches: ${m} -> searchsploit.txt"; showf "${OUT}/searchsploit.txt" 8; }; fi
else skip "nmap"; fi

# ============================================================ PHASE 3
sec "Phase 3 — Web content discovery"
WL=""
[[ -n "$AGGR" ]] && for w in /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt; do [[ -f "$w" ]] && { WL="$w"; break; }; done
[[ -z "$WL" ]] && for w in /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    /usr/share/wordlists/dirb/common.txt; do [[ -f "$w" ]] && { WL="$w"; break; }; done
if [[ -n "$WL" ]]; then info "wordlist: ${WL##*/}"
    D=1; [[ -n "$AGGR" ]] && D=3
    if have feroxbuster; then feroxbuster -u "$URL" -w "$WL" -d "$D" -q -o "${OUT}/content.txt" --no-state >/dev/null 2>&1
    elif have ffuf; then ffuf -u "${URL}/FUZZ" -w "$WL" -of csv -o "${OUT}/content.csv" -s >/dev/null 2>&1; awk -F, 'NR>1{print $2" "$5}' "${OUT}/content.csv" > "${OUT}/content.txt" 2>/dev/null
    elif have gobuster; then gobuster dir -u "$URL" -w "$WL" -q -o "${OUT}/content.txt" >/dev/null 2>&1; fi
    if [[ -s "${OUT}/content.txt" ]]; then ok "paths discovered: $(wc -l < "${OUT}/content.txt")"; showf "${OUT}/content.txt" 12
    else warn "no content discovered (or tool missing)"; fi
else skip "content discovery (no wordlist; sudo apt install seclists)"; fi

# ============================================================ PHASE 4
sec "Phase 4 — Web vulnerability scan"
if have nikto; then info "nikto scanning ${URL} ..."
    if [[ -n "$AGGR" ]]; then nikto -h "$URL" -Tuning x6 -maxtime 1200 > "${OUT}/nikto.txt" 2>&1
    else nikto -h "$URL" -maxtime 600 > "${OUT}/nikto.txt" 2>&1; fi
    nf=$(grep -c '^+ ' "${OUT}/nikto.txt" 2>/dev/null || echo 0); ok "nikto findings: ${nf}"
    grep '^+ ' "${OUT}/nikto.txt" 2>/dev/null | sed 's/^+ /      /' | head -n $([[ -n "$VERBOSE" ]] && echo 999 || echo 10)
else skip "nikto"; fi
if have nuclei; then info "nuclei scanning (all severities) ..."
    X=""; [[ -n "$AGGR" ]] && X="-fr"
    nuclei -u "$URL" -severity info,low,medium,high,critical $X -silent -o "${OUT}/nuclei.txt" >/dev/null 2>&1
    nn=$(cnt "${OUT}/nuclei.txt")
    if [[ "$nn" -gt 0 ]]; then ok "nuclei findings: ${nn}"
        for sev in critical high medium low info; do
            c=$(grep -c "\[${sev}\]" "${OUT}/nuclei.txt" 2>/dev/null || echo 0)
            [[ "$c" -gt 0 ]] && case "$sev" in
                critical|high) printf "      ${RED}${B}%-9s %s${R}\n" "$sev" "$c" ;;
                medium)        printf "      ${YEL}%-9s %s${R}\n" "$sev" "$c" ;;
                *)             printf "      ${DIM}%-9s %s${R}\n" "$sev" "$c" ;;
            esac; done
        grep -iE '\[(critical|high)\]' "${OUT}/nuclei.txt" | sed 's/^/      /' | head -8
    else ok "nuclei findings: 0"; fi
else skip "nuclei"; fi
if grep -qi 'wordpress' "${OUT}/whatweb.txt" 2>/dev/null && have wpscan; then
    E="vp,t"; [[ -n "$AGGR" ]] && E="vp,vt,tt,cb,dbe,u1-50"; info "wpscan (--enumerate ${E}) ..."
    wpscan --url "$URL" --enumerate "$E" --random-user-agent --no-banner > "${OUT}/wpscan.txt" 2>&1
    ok "wpscan -> wpscan.txt"; fi

# ============================================================ PHASE 5
sec "Phase 5 — TLS / SSL"
if [[ "$SCHEME" == https || -n "$FULL" ]]; then
    if have testssl.sh; then testssl.sh --quiet "${HOST}:443" > "${OUT}/testssl.txt" 2>&1; ok "testssl -> testssl.txt"
        grep -iE 'vulnerable|NOT ok|expired|self.signed' "${OUT}/testssl.txt" | sed 's/^/      /' | head -8
    elif have sslscan; then sslscan "${HOST}:443" > "${OUT}/sslscan.txt" 2>&1; ok "sslscan -> sslscan.txt"; showf "${OUT}/sslscan.txt" 8
    elif have nmap; then nmap --script ssl-enum-ciphers -p 443 "$HOST" -oN "${OUT}/ssl-ciphers.txt" >/dev/null 2>&1; ok "ssl-enum-ciphers -> ssl-ciphers.txt"; showf "${OUT}/ssl-ciphers.txt" 10
    else skip "no TLS tool"; fi
else skip "TLS (http target; use https:// or --full)"; fi

# ============================================================ PHASE 6
sec "Phase 6 — API discovery & testing"
if have curl; then
    API_PATHS=( /api /api/v1 /api/v2 /rest /graphql /swagger.json /openapi.json \
        /swagger/v1/swagger.json /api-docs /v2/api-docs /v3/api-docs /swagger-ui.html \
        /.well-known/openid-configuration /actuator /actuator/health /actuator/env /metrics /api/docs )
    : > "${OUT}/api-endpoints.txt"; info "probing common API / doc paths ..."
    for p in "${API_PATHS[@]}"; do
        code=$(curl -s -k -m 10 -o /dev/null -w "%{http_code}" -A "Mozilla/5.0" "${BASE}${p}" 2>/dev/null)
        [[ "$code" =~ ^(200|201|301|302|401|403)$ ]] && echo "${code}  ${BASE}${p}" >> "${OUT}/api-endpoints.txt"
    done
    ae=$(cnt "${OUT}/api-endpoints.txt")
    if [[ "$ae" -gt 0 ]]; then ok "interesting API/doc endpoints: ${ae}"
        while read -r l; do printf "      ${MAG}%s${R}\n" "$l"; done < "${OUT}/api-endpoints.txt"
    else ok "no common API/doc endpoints responded"; fi
    for g in /graphql /api/graphql /v1/graphql /query; do
        gcode=$(curl -s -k -m 10 -o /dev/null -w "%{http_code}" "${BASE}${g}" 2>/dev/null)
        if [[ "$gcode" =~ ^(200|400|405)$ ]]; then
            intro=$(curl -s -k -m 12 -X POST -H "Content-Type: application/json" \
                    -d '{"query":"{__schema{queryType{name}}}"}' "${BASE}${g}" 2>/dev/null)
            echo "$intro" | grep -q "__schema\|queryType" && { hit "GraphQL introspection ENABLED at ${g} (often a misconfig)"; echo "$intro" > "${OUT}/graphql-introspection.txt"; }
        fi
    done
fi
APIWL=""; for w in /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    /usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt; do [[ -f "$w" ]] && { APIWL="$w"; break; }; done
if [[ -n "$APIWL" ]] && have ffuf; then info "ffuf API routes (${APIWL##*/}) ..."
    ffuf -u "${BASE}/FUZZ" -w "$APIWL" -of csv -o "${OUT}/api-routes.csv" -s >/dev/null 2>&1; ok "API routes -> api-routes.csv"; fi
have kr    && { info "kiterunner ..."; kr scan "${BASE}" -A=apiroutes-large > "${OUT}/kiterunner.txt" 2>&1 || true; ok "kiterunner -> kiterunner.txt"; }
have arjun && { info "arjun params ..."; arjun -u "$URL" -oT "${OUT}/arjun-params.txt" >/dev/null 2>&1 || true; ok "arjun -> arjun-params.txt"; }
if have nuclei; then info "nuclei API/exposure templates ..."
    nuclei -u "${BASE}" -tags api,swagger,graphql,exposure -silent -o "${OUT}/nuclei-api.txt" >/dev/null 2>&1 || true
    na=$(cnt "${OUT}/nuclei-api.txt"); [[ "$na" -gt 0 ]] && hit "API nuclei findings: ${na} -> nuclei-api.txt" || ok "API nuclei findings: 0"; fi

# ============================================================ REPORT
DUR=$(( $(date +%s) - START )); ND=$(grep -c "\[" "${OUT}/nuclei.txt" 2>/dev/null || echo 0)
OP=$(grep -cE "^[0-9]+/(tcp|udp) +open" "${OUT}/nmap.txt" 2>/dev/null || echo 0)
NF=$(grep -c '^+ ' "${OUT}/nikto.txt" 2>/dev/null || echo 0)
CT=$(cnt "${OUT}/content.txt"); AE=$(cnt "${OUT}/api-endpoints.txt")
printf "\n${B}${BLU}============================================================\n  SCAN REPORT — %s\n============================================================${R}\n" "$HOST"
printf "  ${B}Duration${R}        : %dm %ds\n" "$((DUR/60))" "$((DUR%60))"
printf "  ${B}Open ports${R}      : %s\n" "$OP"
printf "  ${B}Content paths${R}   : %s\n" "$CT"
printf "  ${B}Nikto findings${R}  : %s\n" "$NF"
printf "  ${B}Nuclei findings${R} : %s  (crit %s / high %s / med %s)\n" "$ND" \
    "$(grep -c '\[critical\]' "${OUT}/nuclei.txt" 2>/dev/null||echo 0)" \
    "$(grep -c '\[high\]' "${OUT}/nuclei.txt" 2>/dev/null||echo 0)" \
    "$(grep -c '\[medium\]' "${OUT}/nuclei.txt" 2>/dev/null||echo 0)"
printf "  ${B}API endpoints${R}   : %s\n" "$AE"
[[ -s "${OUT}/graphql-introspection.txt" ]] && printf "  ${RED}${B}GraphQL introspection: ENABLED${R}\n"
[[ -s "${OUT}/searchsploit.txt" ]] && printf "  ${B}Exploit matches${R} : see searchsploit.txt\n"
hr
printf "  ${B}All raw output in:${R} %s/\n" "$OUT"
( cd "$OUT" && ls -1 | sed 's/^/    - /' )
{ echo; echo "## Files"; ( cd "$OUT" && ls -1 | sed 's/^/- /' ); echo "_Finished:_ $(date) (${DUR}s)"; } >> "$SUMMARY"
printf "  ${B}Summary report:${R} %s\n" "$SUMMARY"
printf "\n  ${DIM}Detection only. Validate findings manually (Burp); exploit only in an authorized lab.${R}\n\n"
