#!/usr/bin/env bash
# Test script for caddy-analyze guard
# Generates traffic that triggers all detection rules:
#   - brute force (401/403 surge)
#   - directory scanning (404 surge)
#   - SQL injection patterns
#   - path traversal
#   - XSS attempts
#   - scanner user-agents
#
# Usage: ./test-guard.sh [target_url] [requests_per_phase]
#   target_url         default http://localhost
#   requests_per_phase default 20
#
# Run guard in another terminal:
#   sudo caddy-analyze guard /var/log/caddy/access.log --auth-limit 5 --notfound-limit 10 --limit 15

set -uo pipefail

TARGET="${1:-http://localhost}"
N="${2:-20}"

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

phase() {
    local name="$1"
    local n="$2"
    echo -e "\n${CYAN}${BOLD}━━━ Phase: $name ($n requests) ━━━${NC}"
}

send() {
    local url="$1"
    local ua="${2:-curl/8.0}"
    local method="${3:-GET}"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X "$method" \
        -A "$ua" \
        --connect-timeout 5 \
        --max-time 10 \
        "$url" 2>/dev/null || echo "000")
    echo -e "  ${method} ${url#${TARGET}} → ${code}"
}

echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}${BOLD}  Guard Test Script${NC}"
echo -e "${CYAN}  Target: $TARGET${NC}"
echo -e "${CYAN}  Requests/phase: $N${NC}"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Phase 1: Brute force — many 401/403 to /login
phase "Brute Force (401/403)" "$N"
for i in $(seq 1 "$N"); do
    send "${TARGET}/login" "Mozilla/5.0" "POST" &
    [ $((i % 10)) -eq 0 ] && wait
done
wait

# Phase 2: Directory scanning — many 404
phase "Directory Scanning (404)" "$N"
SCAN_PATHS=(
    "/admin" "/wp-admin" "/.env" "/config.php" "/phpinfo.php"
    "/wp-login.php" "/xmlrpc.php" "/.git/config" "/backup.zip"
    "/api/secret" "/.htaccess" "/vendor/phpunit" "/node_modules"
    "/.aws/credentials" "/docker-compose.yml"
)
for i in $(seq 1 "$N"); do
    p="${SCAN_PATHS[$((RANDOM % ${#SCAN_PATHS[@]}))]}"
    send "${TARGET}${p}" "dirbuster/0.4" &
    [ $((i % 10)) -eq 0 ] && wait
done
wait

# Phase 3: SQL injection
phase "SQL Injection" "$N"
SQLI_PAYLOADS=(
    "/?id=1%20OR%201=1"
    "/?id=1'%20UNION%20SELECT%20*%20FROM%20users"
    "/?q=1';%20DROP%20TABLE%20users--"
    "/?id=1%20AND%201=1"
    "/login?user=admin'--&pass=x"
    "/?id=1%20UNION%20SELECT%20null,null,null"
    "/?search=';%20EXEC%20xp_cmdshell('dir')--"
    "/?id=1%20OR%20'1'='1"
)
for i in $(seq 1 "$N"); do
    p="${SQLI_PAYLOADS[$((RANDOM % ${#SQLI_PAYLOADS[@]}))]}"
    send "${TARGET}${p}" "sqlmap/1.7" &
    [ $((i % 10)) -eq 0 ] && wait
done
wait

# Phase 4: Path traversal / LFI
phase "Path Traversal / LFI" "$N"
LFI_PATHS=(
    "/../../../etc/passwd"
    "/%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "/?file=../../etc/shadow"
    "/?page=php://filter/convert.base64/resource=index"
    "/../../../proc/self/environ"
    "/?path=....//....//etc/passwd"
    "/%00/etc/passwd"
    "/?file=file:///etc/passwd"
)
for i in $(seq 1 "$N"); do
    p="${LFI_PATHS[$((RANDOM % ${#LFI_PATHS[@]}))]}"
    send "${TARGET}${p}" "nikto/2.5" &
    [ $((i % 10)) -eq 0 ] && wait
done
wait

# Phase 5: XSS attempts
phase "XSS" "$N"
XSS_PATHS=(
    "/?q=<script>alert(1)</script>"
    "/?q=javascript:alert(1)"
    "/?q=<img%20src=x%20onerror=alert(1)>"
    "/?q=<svg/onload=alert(1)>"
    "/?q=%3Cscript%3Ealert(1)%3C/script%3E"
    "/?q=';alert(1);//"
)
for i in $(seq 1 "$N"); do
    p="${XSS_PATHS[$((RANDOM % ${#XSS_PATHS[@]}))]}"
    send "${TARGET}${p}" "Mozilla/5.0" &
    [ $((i % 10)) -eq 0] && wait
done
wait

# Phase 6: Scanner user-agents
phase "Scanner UAs" "$N"
SCANNERS=(
    "sqlmap/1.7" "nikto/2.5" "dirbuster/0.4" "gobuster/3.6"
    "wfuzz/2.4" "nmap/7.94" "ZAP/2.14" "masscan/1.3"
    "hydra/9.5" "openvas/22.4"
)
for i in $(seq 1 "$N"); do
    ua="${SCANNERS[$((RANDOM % ${#SCANNERS[@]}))]}"
    send "${TARGET}/" "$ua" &
    [ $((i % 10)) -eq 0 ] && wait
done
wait

# Phase 7: High volume flood
phase "Volume Flood" "$((N * 3))"
for i in $(seq 1 $((N * 3))); do
    send "${TARGET}/" "Go-http-client/1.1" &
    [ $((i % 20)) -eq 0 ] && wait
done
wait

# Phase 8: Mixed attack — combine everything
phase "Mixed Attack" "$N"
MIXED=(
    "/?id=1%20OR%201=1|sqlmap/1.7"
    "/../../../etc/passwd|nikto/2.5"
    "/?q=<script>alert(1)</script>|dirbuster/0.4"
    "/.env|gobuster/3.6"
    "/login|hydra/9.5|POST"
    "/wp-admin|nmap/7.94"
)
for i in $(seq 1 "$N"); do
    m="${MIXED[$((RANDOM % ${#MIXED[@]}))]}"
    IFS='|' read -r path ua method <<< "$m"
    [ -z "$method" ] && method="GET"
    send "${TARGET}${path}" "$ua" "$method" &
    [ $((i % 10)) -eq 0 ] && wait
done
wait

echo
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  Test complete${NC}"
echo -e "${GREEN}  Check guard output for blocked IPs${NC}"
echo -e "${GREEN}  Run: caddy-analyze unban --list${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
