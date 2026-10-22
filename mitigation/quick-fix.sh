#!/usr/bin/env bash
# php2shell emergency mitigation — disables session.upload_progress
# Usage:
#   sudo ./quick-fix.sh              # apply fix
#   sudo ./quick-fix.sh --check      # check current status
#   sudo ./quick-fix.sh --revert     # undo changes
set -euo pipefail

DIRECTIVE="session.upload_progress.enabled"
TS="$(date +%Y%m%d-%H%M%S)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

find_php_inis() {
    local inis=()
    for bin in $(which php php-fpm php-cgi 2>/dev/null) \
               /usr/bin/php* /usr/sbin/php-fpm* /usr/local/bin/php*; do
        [ -x "$bin" ] 2>/dev/null || continue
        local ini
        ini=$("$bin" -r 'echo php_ini_loaded_file();' 2>/dev/null) || continue
        [ -n "$ini" ] && [ -f "$ini" ] && inis+=("$ini")
        local scandir
        scandir=$("$bin" -r 'echo php_ini_scanned_files();' 2>/dev/null) || continue
        for f in $(echo "$scandir" | tr ',' '\n'); do
            f=$(echo "$f" | xargs)
            [ -f "$f" ] && inis+=("$f")
        done
    done
    printf '%s\n' "${inis[@]}" | sort -u
}

check_status() {
    echo -e "${YELLOW}[*] Checking PHP installations...${NC}"
    local found=0
    for bin in $(which php php-fpm php-cgi 2>/dev/null) \
               /usr/bin/php* /usr/sbin/php-fpm*; do
        [ -x "$bin" ] 2>/dev/null || continue
        local ver sapi val
        ver=$("$bin" -r 'echo PHP_VERSION;' 2>/dev/null) || continue
        sapi=$("$bin" -r 'echo php_sapi_name();' 2>/dev/null) || true
        val=$("$bin" -r "echo ini_get('$DIRECTIVE');" 2>/dev/null) || true
        found=1
        if [ "$val" = "1" ] || [ "$val" = "" ]; then
            echo -e "  ${RED}[VULNERABLE]${NC} $bin (PHP $ver, $sapi) — $DIRECTIVE = On"
        else
            echo -e "  ${GREEN}[MITIGATED]${NC} $bin (PHP $ver, $sapi) — $DIRECTIVE = Off"
        fi
    done
    [ $found -eq 0 ] && echo "  No PHP installations found."
}

apply_fix() {
    echo -e "${YELLOW}[*] Applying mitigation...${NC}"
    while IFS= read -r ini; do
        [ -z "$ini" ] && continue
        if grep -q "^${DIRECTIVE}" "$ini" 2>/dev/null; then
            cp "$ini" "${ini}.bak.${TS}"
            sed -i.tmp "s/^${DIRECTIVE}.*/${DIRECTIVE} = Off/" "$ini"
            rm -f "${ini}.tmp"
            echo -e "  ${GREEN}[FIXED]${NC} $ini (backup: ${ini}.bak.${TS})"
        else
            cp "$ini" "${ini}.bak.${TS}"
            echo "" >> "$ini"
            echo "; php2shell mitigation (${TS})" >> "$ini"
            echo "${DIRECTIVE} = Off" >> "$ini"
            echo -e "  ${GREEN}[ADDED]${NC} $ini (backup: ${ini}.bak.${TS})"
        fi
    done < <(find_php_inis)

    echo ""
    echo -e "${YELLOW}[*] Restarting services...${NC}"
    for svc in php-fpm php8.4-fpm php8.3-fpm php8.2-fpm apache2 httpd nginx; do
        systemctl reload "$svc" 2>/dev/null && \
            echo -e "  ${GREEN}[OK]${NC} $svc reloaded" || true
    done
    echo ""
    echo -e "${GREEN}[+] Done. Verify with: $0 --check${NC}"
}

revert_fix() {
    echo -e "${YELLOW}[*] Reverting last mitigation...${NC}"
    local count=0
    for bak in $(find /etc -name "*.bak.*" -path "*php*" 2>/dev/null | sort -r); do
        local orig="${bak%.bak.*}"
        if [ -f "$orig" ]; then
            cp "$bak" "$orig"
            echo -e "  ${GREEN}[RESTORED]${NC} $orig"
            count=$((count + 1))
        fi
    done
    [ $count -eq 0 ] && echo "  No backups found."
}

case "${1:-}" in
    --check)  check_status ;;
    --revert) revert_fix ;;
    *)        apply_fix ;;
esac
