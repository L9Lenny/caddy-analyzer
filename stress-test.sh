#!/usr/bin/env bash
# Stress test for lusvecciatore.duckdns.org
# Usage: ./stress-test.sh [total_requests] [concurrency]
#   total_requests  default 100
#   concurrency     default 10

set -uo pipefail

TARGET="${TARGET:-http://lusvecciatore.duckdns.org}"
TOTAL="${1:-100}"
CONCURRENCY="${2:-10}"

PATHS=("/" "/api" "/staff" "/login" "/admin" "/svgxd.svg" "/static/css/style.css" "/static/js/app.js" "/wp-admin" "/.env" "/api/users" "/api/config" "/health" "/robots.txt" "/favicon.ico")

USER_AGENTS=("Mozilla/5.0 Chrome/125.0" "Mozilla/5.0 Edg/125.0" "Mozilla/5.0 Safari/605" "curl/8.0.1" "python-requests/2.31.0" "Go-http-client/1.1")
METHODS=("GET" "GET" "GET" "POST" "HEAD")

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN} Target:     ${TARGET}${NC}"
echo -e "${CYAN} Requests:   ${TOTAL}${NC}"
echo -e "${CYAN} Concurrent: ${CONCURRENCY}${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo

# Temp file for results
RESULTS=$(mktemp)
trap 'rm -f "$RESULTS"' EXIT

START=$(date +%s)

run_batch() {
    local np=${#PATHS[@]}
    local nu=${#USER_AGENTS[@]}
    local nm=${#METHODS[@]}

    for i in $(seq 1 "$TOTAL"); do
        (
            path="${PATHS[$((RANDOM % np))]}"
            ua="${USER_AGENTS[$((RANDOM % nu))]}"
            method="${METHODS[$((RANDOM % nm))]}"

            code=$(curl -s -o /dev/null -w "%{http_code}" \
                -X "$method" \
                -A "$ua" \
                --connect-timeout 5 \
                --max-time 10 \
                "${TARGET}${path}" 2>/dev/null || echo "000")

            case "$code" in
                2*) printf "%b[%d] %s %s → %s%b\n" "$GREEN" "$i" "$method" "$path" "$code" "$NC" ;;
                3*) printf "%b[%d] %s %s → %s%b\n" "$YELLOW" "$i" "$method" "$path" "$code" "$NC" ;;
                *)  printf "%b[%d] %s %s → %s%b\n" "$RED" "$i" "$method" "$path" "$code" "$NC" ;;
            esac

            echo "$code" >> "$RESULTS"
        ) &
        # Limit concurrency
        while [ "$(jobs -r | wc -l)" -ge "$CONCURRENCY" ]; do
            sleep 0.05
        done
    done
    wait
}

run_batch

END=$(date +%s)
ELAPSED=$((END - START))

# Tally
total=0
codes_2xx=0
codes_3xx=0
codes_4xx=0
codes_5xx=0
codes_0xx=0

while IFS= read -r code; do
    total=$((total + 1))
    case "$code" in
        2*) codes_2xx=$((codes_2xx + 1)) ;;
        3*) codes_3xx=$((codes_3xx + 1)) ;;
        4*) codes_4xx=$((codes_4xx + 1)) ;;
        5*) codes_5xx=$((codes_5xx + 1)) ;;
        *)  codes_0xx=$((codes_0xx + 1)) ;;
    esac
done < "$RESULTS"

echo
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN} Results${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Total:    $total"
echo -e "  2xx:      ${GREEN}${codes_2xx}${NC}"
echo -e "  3xx:      ${YELLOW}${codes_3xx}${NC}"
echo -e "  4xx:      ${RED}${codes_4xx}${NC}"
echo -e "  5xx:      ${RED}${codes_5xx}${NC}"
echo -e "  Failed:   ${RED}${codes_0xx}${NC}"
echo -e "  Elapsed:  ${ELAPSED}s"
if [ "$ELAPSED" -gt 0 ]; then
    rps=$(awk "BEGIN {printf \"%.1f\", $total / $ELAPSED}")
    echo -e "  RPS:      $rps"
fi
echo
